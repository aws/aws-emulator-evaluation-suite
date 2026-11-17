"""deploy-cdk-bucket-deployment-prefix-noprune-metadata-denied-put-rejected."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-bucket-deployment-prefix-noprune-metadata-denied-put-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "logs", "s3", "ssm", "sts"]

_APP = "bucket_deployment_prefix_metadata_noprune"

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _denied_sync_reason(bucket: str, key_prefix: str) -> str:
    """The Custom::CDKBucketDeployment CREATE_FAILED reason when `aws s3 sync` to ``bucket`` is
    denied, with the handler's temporary work directory and the RequestId masked."""
    return (
        "Received response status [FAILED] from custom resource. Message returned: Command "
        "'['/opt/awscli/aws', 's3', 'sync', '<workdir>/contents', "
        f"'s3://{bucket}/{key_prefix}', '--content-type', 'text/x-sim2real', "
        "'--cache-control', 'max-age=3600', '--metadata-directive', 'REPLACE']' returned "
        "non-zero exit status 1. (RequestId: <id>)"
    )


def _masked(reason: str) -> str:
    """``reason`` with only the handler's temporary work directory and RequestId masked."""
    reason = re.sub(r"'/tmp/tmp[A-Za-z0-9_]+/contents'", "'<workdir>/contents'", reason)
    return re.sub(rf"\(RequestId: {_UUID}\)$", "(RequestId: <id>)", reason)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A BucketDeployment with a destinationKeyPrefix, prune:false and system metadata is refused
    and lands nothing against a destination denying s3:PutObject; the identical construct lands
    against an unrestricted bucket, and retainOnDelete:false removes it on destroy.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    caller = ctx.client("sts").get_caller_identity()
    account = caller["Account"]
    partition = caller["Arn"].split(":")[1]
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    ok_stack = ctx.unique_name("sim2real-bucketdeploy-ok-")
    deny_stack = ctx.unique_name("sim2real-bucketdeploy-deny-")
    ok_bucket = ctx.unique_name("sim2real-bucketdeploy-ok-")
    deny_bucket = ctx.unique_name("sim2real-bucketdeploy-deny-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    key_prefix = "sim2real-data/"

    work = _stage_app(ctx, _APP)
    sources = Path(tempfile.mkdtemp(prefix="sim2real-bucketdeploy-src-"))
    ctx.on_cleanup(lambda: shutil.rmtree(sources, ignore_errors=True))

    kept_marker = ctx.unique_name("kept-")
    dropped_marker = ctx.unique_name("dropped-")
    v1 = sources / "v1"
    v1.mkdir()
    (v1 / "kept.txt").write_text(kept_marker)
    (v1 / "dropped.txt").write_text(dropped_marker)
    v2 = sources / "v2"
    v2.mkdir()
    (v2 / "kept.txt").write_text(kept_marker)

    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    location: dict = {}
    if ctx.region != "us-east-1":
        location = {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=ok_bucket, **location)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, ok_bucket))
    s3.create_bucket(Bucket=deny_bucket, **location)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, deny_bucket))
    s3.put_bucket_policy(
        Bucket=deny_bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Sim2realDenyPut",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:{partition}:s3:::{deny_bucket}/*",
                    }
                ],
            }
        ),
    )

    fn_names: list[str] = []
    body_error: BaseException | None = None
    try:
        _bootstrap(ctx, account, qualifier, toolkit_stack)

        # 1. REJECTED: the denied destination's Create fails and nothing lands there.
        rc, out = _cdk(
            ctx,
            work,
            ["deploy", deny_stack, "--require-approval", "never"],
            _env(ctx, account, qualifier, deny_stack, deny_bucket, key_prefix, v1),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=None,
        )
        fn_names.extend(_stack_lambda_functions(cfn, deny_stack))
        assert rc != 0, (
            f"`cdk deploy` exited 0 against destination bucket {deny_bucket!r}, whose policy "
            f"denies s3:PutObject. Output tail: {out[-1000:]!r}"
        )
        status, reason = _rollback_status_and_reason(ctx, cfn, deny_stack, "CREATE_FAILED")
        assert status == "ROLLBACK_COMPLETE", (
            f"stack {deny_stack!r} reached {status!r}, expected ROLLBACK_COMPLETE after the "
            f"denied create. Reason: {reason!r}"
        )
        want_reason = _denied_sync_reason(deny_bucket, key_prefix)
        assert _masked(reason) == want_reason, (
            f"the Custom::CDKBucketDeployment failure reason was {reason!r}, expected "
            f"{want_reason!r} (masked)"
        )
        assert _bucket_keys(s3, deny_bucket) == set(), (
            f"the denied bucket {deny_bucket!r} holds {sorted(_bucket_keys(s3, deny_bucket))} "
            f"after the refused create — a refusal must leave no object behind"
        )

        # 2. CREATE (control): the identical construct against an unrestricted bucket lands
        #    under the prefix with the declared system metadata.
        _cdk(
            ctx,
            work,
            ["deploy", ok_stack, "--require-approval", "never"],
            _env(ctx, account, qualifier, ok_stack, ok_bucket, key_prefix, v1),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        fn_names.extend(_stack_lambda_functions(cfn, ok_stack))

        keys_after_create = _bucket_keys(s3, ok_bucket)
        assert keys_after_create == {f"{key_prefix}kept.txt", f"{key_prefix}dropped.txt"}, (
            f"after deploy, {ok_bucket!r} holds keys {sorted(keys_after_create)}, expected "
            f"exactly the two source files under {key_prefix!r}"
        )
        head = s3.head_object(Bucket=ok_bucket, Key=f"{key_prefix}kept.txt")
        assert head["ContentType"] == "text/x-sim2real", (
            f"kept.txt's ContentType was {head['ContentType']!r}, expected the declared system "
            f"metadata 'text/x-sim2real'"
        )
        assert head["CacheControl"] == "max-age=3600", (
            f"kept.txt's CacheControl was {head.get('CacheControl')!r}, expected the declared "
            f"system metadata 'max-age=3600'"
        )

        # 3. UPDATE (control): dropping dropped.txt from the source does NOT remove it, because
        #    this deployment sets prune:false (the opposite of the construct's default).
        _cdk(
            ctx,
            work,
            ["deploy", ok_stack, "--require-approval", "never"],
            _env(ctx, account, qualifier, ok_stack, ok_bucket, key_prefix, v2),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        keys_after_noprune = _bucket_keys(s3, ok_bucket)
        assert keys_after_noprune == {f"{key_prefix}kept.txt", f"{key_prefix}dropped.txt"}, (
            f"after the update dropping dropped.txt from the source, {ok_bucket!r} holds keys "
            f"{sorted(keys_after_noprune)}; with prune=false the file must survive"
        )

        # 4. DESTROY: the explicit retainOnDelete:false removes the surviving deployment.
        _cdk(
            ctx,
            work,
            ["destroy", ok_stack, "--force"],
            _env(ctx, account, qualifier, ok_stack, ok_bucket, key_prefix, v2),
            timeout_s=_DEPLOY_TIMEOUT_S,
            expect_rc=0,
        )
        _wait_for_stack_absent(ctx, cfn, ok_stack)
        s3.head_bucket(Bucket=ok_bucket)
        keys_after_destroy = _bucket_keys(s3, ok_bucket)
        assert keys_after_destroy == set(), (
            f"after the stack was destroyed, {ok_bucket!r} holds keys "
            f"{sorted(keys_after_destroy)}, expected none — retainOnDelete:false must remove "
            f"the deployed objects"
        )
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        try:
            _teardown(
                ctx,
                account,
                [deny_stack, ok_stack],
                toolkit_stack,
                staging_bucket,
                qualifier,
                fn_names,
            )
        except Exception as teardown_error:
            if body_error is None:
                raise
            # The body's failure is the verdict; the teardown failure rides along with it.
            body_error.add_note(f"teardown also failed: {teardown_error!r}")


def _env(
    ctx,
    account: str,
    qualifier: str,
    stack: str,
    dest_bucket: str,
    key_prefix: str,
    source_dir: Path,
) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = account
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["DEST_BUCKET"] = dest_bucket
    env["KEY_PREFIX"] = key_prefix
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
    try:
        return _stack_lambda_functions(cfn, stack)
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return []
        raise


def _is_stack_not_found(exc: ClientError, stack: str) -> bool:
    """Whether ``exc`` is exactly CloudFormation's not-found for the stack name or id ``stack``."""
    error = exc.response["Error"]
    return (error.get("Code"), error.get("Message")) == (
        "ValidationError",
        f"Stack with id {stack} does not exist",
    )


def _rollback_status_and_reason(
    ctx, cfn, stack: str, failed_status: str, *, timeout_s: float = 420.0
) -> tuple[str, str]:
    """Poll to a terminal status, returning it with the one failed deployment's StatusReason."""
    status = _poll_status(cfn, stack, lambda s: not s.endswith("_IN_PROGRESS"), timeout_s, ctx)
    reasons = [
        event.get("ResourceStatusReason", "")
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
        for event in page["StackEvents"]
        if event["ResourceType"] == "Custom::CDKBucketDeployment"
        and event.get("ResourceStatus") == failed_status
    ]
    assert len(reasons) == 1, (
        f"stack {stack!r} ({status}) has {len(reasons)} {failed_status} "
        f"Custom::CDKBucketDeployment rows, expected one: {reasons!r}"
    )
    return status, reasons[0]


def _reap_log_group(
    ctx, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0
) -> None:
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _run_tool(ctx, cmd: list[str], cwd: Path, env: dict[str, str], timeout_s: float):
    """subprocess.run capped by the run budget; a run the budget ended raises TimeoutError."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=_budget_s(ctx, timeout_s)
        )
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"`{' '.join(cmd[:2])}`: the run budget ended first; not graded"
            ) from None
        raise


def _stack_status(cfn, stack: str) -> str:
    """The status of the stack name or id ``stack``; the exact not-found reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return "DELETE_COMPLETE"
        raise


def _poll_status(cfn, stack: str, done, timeout_s: float, ctx=None) -> str:
    """Poll the stack's status every 5 s until ``done(status)``; raise at the deadline."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = _stack_status(cfn, stack)
        if done(status):
            return status
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"stack {stack!r}: the run budget ended first; not graded")
            raise AssertionError(f"stack {stack!r} still {status!r} after {timeout_s:.0f}s")
        time.sleep(5.0)


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), f"the CDK app this check references is missing: {source}"
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(
        source,
        staged,
        ignore=shutil.ignore_patterns("cdk.out", "out-*", ".venv", "__pycache__", "node_modules"),
    )
    return staged


def _cdk(
    ctx,
    work: Path,
    args: list[str],
    env: dict[str, str],
    *,
    timeout_s: float,
    expect_rc: int | None,
) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color", "--no-notices"]
    result = _run_tool(ctx, cmd, work, env, timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1500:]!r}"
        )
    return result.returncode, output


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk",
        "bootstrap",
        f"aws://{account}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        toolkit_stack,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--ci",
        "--no-notices",
        "--tags",
        f"sim2real={CHECK}",
    ]
    result = _run_tool(ctx, command, scratch, ctx.subprocess_env(), _BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete the stack by its StackId, whatever its state; raise unless DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = _poll_status(
        cfn,
        stack_id,
        lambda s: (
            not s.endswith("_IN_PROGRESS") or s in ("DELETE_IN_PROGRESS", "REVIEW_IN_PROGRESS")
        ),
        timeout_s,
    )
    if status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        status = _poll_status(
            cfn,
            stack_id,
            lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
            max(30.0, deadline - time.monotonic()),
        )
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack!r} ({stack_id}) ended {status!r}, not DELETE_COMPLETE")


def _wait_for_stack_absent(ctx, cfn, stack: str, *, timeout_s: float = 420.0) -> None:
    """Wait until the stack name ``stack`` reads as gone; DELETE_FAILED raises at once."""
    status = _poll_status(
        cfn, stack, lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), timeout_s, ctx
    )
    assert status == "DELETE_COMPLETE", f"stack {stack!r} reached {status!r}"


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


def _teardown(
    ctx,
    account: str,
    stacks: list[str],
    toolkit_stack: str | None,
    staging_bucket: str,
    qualifier: str,
    fn_names: list[str],
) -> None:
    """Delete every app stack and everything bootstrap left.

    Inline rather than `ctx.on_cleanup`, whose 60s cap cannot cover the bootstrap teardown.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    ecr_repo = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"

    def collect() -> None:
        for stack in stacks:
            for name in _existing_stack_lambda_functions(ctx.client("cloudformation"), stack):
                if name not in fn_names:
                    fn_names.append(name)

    for label, step in [("function names of the app stacks", collect)]:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    steps: list[tuple[str, object]] = [
        (
            f"app stack {stack}",
            lambda stack=stack: _delete_stack_and_wait(
                ctx, stack, timeout_s=max(30.0, deadline - time.monotonic())
            ),
        )
        for stack in stacks
    ]
    for fn_name in fn_names:
        steps.append(
            (f"log group of {fn_name}", lambda n=fn_name: _reap_log_group(ctx, f"/aws/lambda/{n}"))
        )
    if toolkit_stack:
        steps += [
            (
                f"staging bucket {staging_bucket}",
                lambda: _empty_and_delete_bucket(ctx, staging_bucket),
            ),
            (
                f"toolkit stack {toolkit_stack}",
                lambda: _delete_stack_and_wait(
                    ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic())
                ),
            ),
            (f"container assets repository {ecr_repo}", lambda: _delete_ecr_repo(ctx, ecr_repo)),
        ]
    for label, step in steps:
        if label == f"staging bucket {staging_bucket}" and any(
            p.startswith("app stack ") for p in problems
        ):
            raise AssertionError(
                f"toolkit stack {toolkit_stack} and staging bucket kept: " + "; ".join(problems)
            )
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")

    if toolkit_stack:
        remaining: list[str] = ["teardown verification never ran"]
        try:
            while True:
                remaining = _bootstrap_remnants(
                    ctx, toolkit_stack, staging_bucket, qualifier, ecr_repo
                )
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


def _bootstrap_remnants(
    ctx, toolkit_stack: str, staging_bucket: str, qualifier: str, ecr_repo: str
) -> list[str]:
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(StackName=toolkit_stack)["Stacks"][0][
            "StackStatus"
        ]
        remaining.append(f"toolkit stack {toolkit_stack} ({status})")
    except ClientError as exc:
        if not _is_stack_not_found(exc, toolkit_stack):
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
