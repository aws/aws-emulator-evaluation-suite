"""deploy-cdk-bucket-deployment-lands-prunes-and-retains-on-destroy."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-bucket-deployment-lands-prunes-and-retains-on-destroy"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_APP = "bucket_deployment_lifecycle"

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A custom-resource-backed aws_s3_deployment.BucketDeployment lands its source bytes in the
    destination bucket, an update dropping a source file prunes exactly that key (default
    `prune`), and destroying the stack retains the bucket and its object (default `retainOnDelete`).
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-bucketdeploy-")
    dest_bucket = ctx.unique_name("sim2real-bucketdeploy-dest-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    work = _stage_app(ctx, _APP)
    sources = Path(tempfile.mkdtemp(prefix="sim2real-bucketdeploy-src-"))
    ctx.on_cleanup(lambda: shutil.rmtree(sources, ignore_errors=True))

    keep_marker = ctx.unique_name("keep-")
    prune_marker = ctx.unique_name("prune-")
    v1 = sources / "v1"
    v1.mkdir()
    (v1 / "keep.txt").write_text(keep_marker)
    (v1 / "prune-me.txt").write_text(prune_marker)
    v2 = sources / "v2"
    v2.mkdir()
    (v2 / "keep.txt").write_text(keep_marker)

    bootstrapped = False
    fn_names: list[str] = []
    try:
        _bootstrap(ctx, account, qualifier, toolkit_stack)
        bootstrapped = True

        # 1. deploy: the destination bucket gets exactly the source's keys and bytes.
        _cdk(ctx, work, ["deploy", "--require-approval", "never"],
             _env(ctx, account, qualifier, stack, dest_bucket, v1), timeout_s=_DEPLOY_TIMEOUT_S,
             expect_rc=0)
        # The custom resource's Lambda function creates its own log group on first invoke; the
        # stack does not own it, so its name is read now, while the function still exists.
        fn_names.extend(_stack_lambda_functions(cfn, stack))

        keys_after_deploy = _bucket_keys(s3, dest_bucket)
        assert keys_after_deploy == {"keep.txt", "prune-me.txt"}, (
            f"after deploy, {dest_bucket!r} holds keys {sorted(keys_after_deploy)}, expected "
            f"exactly {{'keep.txt', 'prune-me.txt'}}"
        )
        assert _object_bytes(s3, dest_bucket, "keep.txt") == keep_marker.encode(), (
            f"keep.txt in {dest_bucket!r} does not carry the source bytes {keep_marker!r}"
        )
        assert _object_bytes(s3, dest_bucket, "prune-me.txt") == prune_marker.encode(), (
            f"prune-me.txt in {dest_bucket!r} does not carry the source bytes {prune_marker!r}"
        )

        # 2. update: dropping prune-me.txt from the source prunes it (the default `prune: true`);
        #    keep.txt, still in the source, survives with its original bytes.
        _cdk(ctx, work, ["deploy", "--require-approval", "never"],
             _env(ctx, account, qualifier, stack, dest_bucket, v2), timeout_s=_DEPLOY_TIMEOUT_S,
             expect_rc=0)

        keys_after_update = _bucket_keys(s3, dest_bucket)
        assert keys_after_update == {"keep.txt"}, (
            f"after the update dropping prune-me.txt, {dest_bucket!r} holds keys "
            f"{sorted(keys_after_update)}, expected exactly {{'keep.txt'}} — the default prune "
            f"did not remove the file the update stopped sourcing"
        )
        assert _object_bytes(s3, dest_bucket, "keep.txt") == keep_marker.encode(), (
            f"keep.txt in {dest_bucket!r} changed bytes across the update that only dropped "
            f"prune-me.txt"
        )
        pruned_error = _error(lambda: s3.head_object(Bucket=dest_bucket, Key="prune-me.txt"))
        assert pruned_error == ("404", "Not Found"), (
            f"HeadObject on the pruned key prune-me.txt returned {pruned_error!r}, expected a "
            f"404 Not Found — the key must be gone, not merely stale"
        )

        # 3. destroy: the default `retainOnDelete` (true) means the custom resource deletes
        #    nothing on the stack's delete event, and the bucket's own default removal policy
        #    (RETAIN) means CloudFormation does not delete the bucket either — so the surviving
        #    object is still there after the stack itself is gone.
        _cdk(ctx, work, ["destroy", "--force"],
             _env(ctx, account, qualifier, stack, dest_bucket, v2),
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        _wait_for_stack_absent(cfn, stack)

        try:
            s3.head_bucket(Bucket=dest_bucket)
        except ClientError as exc:
            raise AssertionError(
                f"HeadBucket on {dest_bucket!r} after the stack was destroyed returned "
                f"{exc.response['Error'].get('Code')!r}, expected 200 — the default "
                f"retainOnDelete must leave the destination bucket in place"
            ) from exc
        keys_after_destroy = _bucket_keys(s3, dest_bucket)
        assert keys_after_destroy == {"keep.txt"}, (
            f"after the stack was destroyed, {dest_bucket!r} holds keys "
            f"{sorted(keys_after_destroy)}, expected the retained {{'keep.txt'}} — the default "
            f"retainOnDelete must not delete the deployed object"
        )
        assert _object_bytes(s3, dest_bucket, "keep.txt") == keep_marker.encode(), (
            f"keep.txt in the retained bucket {dest_bucket!r} no longer carries the bytes it was "
            f"deployed with"
        )
    finally:
        _teardown(ctx, account, stack, dest_bucket, toolkit_stack if bootstrapped else None,
                 staging_bucket, qualifier, fn_names)


def _env(ctx, account: str, qualifier: str, stack: str, dest_bucket: str,
         source_dir: Path) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = account
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["DEST_BUCKET"] = dest_bucket
    env["SOURCE_DIR"] = str(source_dir)
    return env


def _stack_lambda_functions(cfn, stack: str) -> list[str]:
    names: list[str] = []
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
        for res in page["StackResourceSummaries"]:
            if res["ResourceType"] == "AWS::Lambda::Function" and res.get("PhysicalResourceId"):
                names.append(res["PhysicalResourceId"])
    return names


def _existing_stack_lambda_functions(cfn, stack: str) -> list[str]:
    """The stack's function names, including deleted ones after a rollback; none if it is gone."""
    try:
        return _stack_lambda_functions(cfn, stack)
    except ClientError as exc:
        if _is_stack_not_found(exc):
            return []
        raise


def _is_stack_not_found(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error.get("Code") == "ValidationError" and "does not exist" in error.get("Message", "")


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered invocation can flush its log stream after the function is deleted and recreate
    the group, so one delete is one round, not a teardown.
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


def _bucket_keys(s3, bucket: str) -> set[str]:
    keys: set[str] = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys |= {o["Key"] for o in page.get("Contents", [])}
    return keys


def _object_bytes(s3, bucket: str, key: str) -> bytes:
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError("call succeeded but was expected to be refused")


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), f"the CDK app this check references is missing: {source}"
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], env: dict[str, str], *, timeout_s: float,
         expect_rc: int) -> None:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color", "--no-notices"]
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=timeout_s)
    output = result.stdout + result.stderr
    assert result.returncode == expect_rc, (
        f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
        f"{output[-1500:]!r}"
    )


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci", "--no-notices",
        "--tags", f"sim2real={CHECK}",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack)
    _wait_for_stack_absent(cfn, stack, timeout_s=timeout_s)


def _wait_for_stack_absent(cfn, stack: str, *, timeout_s: float = 420.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _is_stack_not_found(exc):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _teardown(ctx, account: str, stack: str, dest_bucket: str, toolkit_stack: str | None,
             staging_bucket: str, qualifier: str, fn_names: list[str]) -> None:
    """Delete the app stack, the retained destination bucket, and everything bootstrap left.

    Inline rather than `ctx.on_cleanup`, whose 60s cap cannot cover the bootstrap teardown.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    ecr_repo = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    # A failed create rolls back and deletes the handler after it may have logged; the
    # rolled-back stack still lists the function's physical id.
    def collect() -> None:
        for name in _existing_stack_lambda_functions(ctx.client("cloudformation"), stack):
            if name not in fn_names:
                fn_names.append(name)

    for label, step in [(f"function names of {stack}", collect)]:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    steps: list[tuple[str, object]] = [
        (f"app stack {stack}",
         lambda: _delete_stack_and_wait(ctx, stack, timeout_s=max(30.0, deadline - time.monotonic()))),
        (f"destination bucket {dest_bucket}", lambda: _empty_and_delete_bucket(ctx, dest_bucket)),
    ]
    for fn_name in fn_names:
        steps.append((f"log group of {fn_name}",
                      lambda n=fn_name: _reap_log_group(ctx, f"/aws/lambda/{n}")))
    if toolkit_stack:
        steps += [
            (f"staging bucket {staging_bucket}",
             lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
            (f"toolkit stack {toolkit_stack}",
             lambda: _delete_stack_and_wait(
                 ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic()))),
            (f"container assets repository {ecr_repo}",
             lambda: _delete_ecr_repo(ctx, ecr_repo)),
        ]
    for label, step in steps:
        if label == f"staging bucket {staging_bucket}" and any(
                p.startswith("app stack ") for p in problems):
            # An app stack deletes as the toolkit's exec role: deleting the toolkit strands it.
            raise AssertionError(f"toolkit stack {toolkit_stack} and staging bucket kept: "
                                 + "; ".join(problems))
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")

    if toolkit_stack:
        remaining: list[str] = ["teardown verification never ran"]
        try:
            while True:
                remaining = _bootstrap_remnants(ctx, toolkit_stack, staging_bucket, qualifier,
                                                ecr_repo)
                if not remaining or time.monotonic() > deadline:
                    break
                time.sleep(5.0)
        except Exception as exc:  # noqa: BLE001 — raised with every failure collected so far
            problems.append(f"bootstrap remnant verification failed: {exc!r}")
            raise AssertionError("teardown left residue: " + "; ".join(problems)) from exc
        if remaining:
            problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError("teardown left residue: " + "; ".join(problems))


def _delete_ecr_repo(ctx, repo: str) -> None:
    try:
        ctx.client("ecr").delete_repository(repositoryName=repo, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _bootstrap_remnants(ctx, toolkit_stack: str, staging_bucket: str, qualifier: str,
                        ecr_repo: str) -> list[str]:
    """One read of every bootstrap resource; only each resource's own not-found counts as absent."""
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(
            StackName=toolkit_stack)["Stacks"][0]["StackStatus"]
        remaining.append(f"toolkit stack {toolkit_stack} ({status})")
    except ClientError as exc:
        if not _is_stack_not_found(exc):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append(f"ssm parameter /cdk-bootstrap/{qualifier}/version")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[ecr_repo])
        remaining.append(f"container assets repository {ecr_repo}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
    iam = ctx.client("iam")
    roles = [
        role["RoleName"]
        for page in iam.get_paginator("list_roles").paginate()
        for role in page["Roles"]
        if role["RoleName"].startswith(f"cdk-{qualifier}-")
    ]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
