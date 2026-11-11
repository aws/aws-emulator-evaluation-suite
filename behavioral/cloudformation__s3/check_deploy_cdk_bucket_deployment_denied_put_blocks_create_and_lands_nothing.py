"""deploy-cdk-bucket-deployment-denied-put-blocks-create-and-lands-nothing."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-bucket-deployment-denied-put-blocks-create-and-lands-nothing"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_APP = "bucket_deployment_denied_put"

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """When the destination bucket's own policy denies s3:PutObject, a custom-resource-backed
    aws_s3_deployment.BucketDeployment's Create fails, the stack rolls back, and no object lands;
    a control deploy of the same template against an unrestricted bucket succeeds and lands.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    allowed_stack = ctx.unique_name("sim2real-bucketdeploy-ok-")
    denied_stack = ctx.unique_name("sim2real-bucketdeploy-deny-")
    allowed_bucket = ctx.unique_name("sim2real-bucketdeploy-ok-")
    denied_bucket = ctx.unique_name("sim2real-bucketdeploy-deny-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    # Registered before anything is created; it runs after the bucket cleanups registered below.
    ctx.on_cleanup(lambda: _teardown(ctx, [allowed_stack, denied_stack], toolkit_stack,
                                     staging_bucket, qualifier, account))
    work = _stage_app(ctx, _APP)
    sources = Path(tempfile.mkdtemp(prefix="sim2real-bucketdeploy-src-"))
    ctx.on_cleanup(lambda: shutil.rmtree(sources, ignore_errors=True))
    marker = ctx.unique_name("marker-")
    (sources / "payload.txt").write_text(marker)

    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    location: dict = {}
    if ctx.region != "us-east-1":
        location = {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}

    _bootstrap(ctx, account, qualifier, toolkit_stack)

    s3.create_bucket(Bucket=allowed_bucket, **location)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, allowed_bucket))
    s3.create_bucket(Bucket=denied_bucket, **location)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, denied_bucket))
    s3.put_bucket_policy(Bucket=denied_bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Sim2realDenyPut", "Effect": "Deny", "Principal": "*",
            "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{denied_bucket}/*",
        }],
    }))

    # Positive control: the identical template against an unrestricted bucket succeeds and
    # the file lands, establishing that the template and source are not themselves the cause.
    _cdk(ctx, work, ["deploy", "--require-approval", "never"],
         _env(ctx, account, qualifier, allowed_stack, allowed_bucket, sources),
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    assert _bucket_keys(s3, allowed_bucket) == {"payload.txt"}, (
        f"control: {allowed_bucket!r} holds {sorted(_bucket_keys(s3, allowed_bucket))}, "
        f"expected the deployed {{'payload.txt'}} — the control arm must prove delivery works"
    )
    assert _object_bytes(s3, allowed_bucket, "payload.txt") == marker.encode(), (
        "control: payload.txt in the unrestricted bucket does not carry the source bytes"
    )

    # The deny: the same template, pointed at the bucket that denies s3:PutObject, must be
    # refused — the Create event fails, the stack rolls back, and nothing lands.
    rc, output = _cdk_allow_failure(
        ctx, work, ["deploy", "--require-approval", "never"],
        _env(ctx, account, qualifier, denied_stack, denied_bucket, sources),
        timeout_s=_DEPLOY_TIMEOUT_S)
    assert rc != 0, (
        f"`cdk deploy` exited 0 against a destination bucket {denied_bucket!r} whose policy "
        f"denies s3:PutObject — the custom resource's write was accepted. Output tail: "
        f"{output[-1000:]!r}"
    )

    status, reason = _terminal_stack_status(cfn, denied_stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {denied_stack!r} reached {status!r}, expected ROLLBACK_COMPLETE after the "
        f"custom resource's Create was denied. Reason: {reason!r}"
    )
    # The handler wraps the `aws s3 sync` CLI's own stderr inside a generic exit-status
    # message rather than relaying AWS's error code, so the known, stable part of the
    # message is the command it ran and the non-zero exit it got, naming this bucket.
    assert "Received response status [FAILED] from custom resource." in reason, (
        f"the Custom::CDKBucketDeployment resource's failure reason was {reason!r}; expected "
        f"a custom-resource FAILED response, not some other kind of failure"
    )
    assert "'s3', 'sync', '--delete'" in reason, (
        f"failure reason {reason!r} does not name the `aws s3 sync --delete` command the "
        f"handler runs to land the deployment"
    )
    assert f"s3://{denied_bucket}/']' returned non-zero exit status 1." in reason, (
        f"failure reason {reason!r} does not show the sync targeting {denied_bucket!r} "
        f"exiting non-zero — the one difference from the control arm is this bucket's deny "
        f"policy, so the sync against it is what must be shown failing"
    )

    assert _bucket_keys(s3, denied_bucket) == set(), (
        f"the denied bucket {denied_bucket!r} holds {sorted(_bucket_keys(s3, denied_bucket))} "
        f"after the refused deploy — a refusal must leave no object behind"
    )


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


def _stack_missing(exc: ClientError, stack: str) -> bool:
    """CloudFormation's own answer for a stack that does not exist; anything else is an error."""
    err = exc.response["Error"]
    return (err["Code"] == "ValidationError"
            and f"Stack with id {stack} does not exist" in err.get("Message", ""))


def _stack_lambda_functions(cfn, stack: str) -> list[str]:
    """The functions a stack created, read from its events so a rolled-back stack still names them."""
    names: set[str] = set()
    try:
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
            for event in page["StackEvents"]:
                if (event["ResourceType"] == "AWS::Lambda::Function"
                        and event.get("PhysicalResourceId")):
                    names.add(event["PhysicalResourceId"])
    except ClientError as exc:
        if not _stack_missing(exc, stack):
            raise
    return sorted(names)


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
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
    rc, output = _cdk_allow_failure(ctx, work, args, env, timeout_s=timeout_s)
    assert rc == expect_rc, (
        f"`cdk {' '.join(args)}` exited {rc}, expected {expect_rc}; output tail: "
        f"{output[-1500:]!r}"
    )


def _cdk_allow_failure(ctx, work: Path, args: list[str], env: dict[str, str], *,
                       timeout_s: float) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=timeout_s)
    return result.returncode, result.stdout + result.stderr


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


def _terminal_stack_status(cfn, stack: str, *, timeout_s: float = 420.0) -> tuple[str, str]:
    """Poll to a terminal status, returning it with the failed resource's StatusReason."""
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            break
        time.sleep(5.0)
    reason = ""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if (event["ResourceType"] == "Custom::CDKBucketDeployment"
                    and event.get("ResourceStatus") == "CREATE_FAILED"):
                reason = event.get("ResourceStatusReason", "")
                break
        if reason:
            break
    return status, reason


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc, stack):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
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


def _teardown(ctx, stacks: list[str], toolkit_stack: str, staging_bucket: str,
              qualifier: str, account: str) -> None:
    """Delete the app stacks, their log groups and bootstrap's leftovers; raise naming any left."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    cfn = ctx.client("cloudformation")
    problems: list[str] = []
    fn_names: list[str] = []
    for stack in stacks:
        try:
            fn_names += _stack_lambda_functions(cfn, stack)
        except Exception as exc:  # noqa: BLE001 — run every step, then raise naming each failure
            problems.append(f"functions of app stack {stack}: {exc!r}")
    steps: list[tuple[str, object]] = [
        (f"app stack {stack}",
         lambda s=stack: _delete_stack_and_wait(ctx, s, timeout_s=max(30.0, deadline - time.monotonic())))
        for stack in stacks
    ]
    for fn_name in fn_names:
        steps.append((f"log group of {fn_name}",
                      lambda n=fn_name: _reap_log_group(
                          ctx, f"/aws/lambda/{n}",
                          budget_s=max(30.0, deadline - time.monotonic()))))
    steps += [
        (f"staging bucket {staging_bucket}",
         lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
        (f"toolkit stack {toolkit_stack}",
         lambda: _delete_stack_and_wait(
             ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in steps:
        if label == f"staging bucket {staging_bucket}" and any(
                p.startswith("app stack ") for p in problems):
            # An app stack deletes as the toolkit's exec role: deleting the toolkit strands it.
            raise AssertionError(f"toolkit stack {toolkit_stack} and staging bucket kept: "
                                 + "; ".join(problems))
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — run every step, then raise naming each failure
            problems.append(f"{label}: {exc!r}")

    try:
        remaining = _bootstrap_remnants(ctx, toolkit_stack, staging_bucket, qualifier, account)
    except Exception as exc:  # noqa: BLE001 — raised with every failure collected so far
        problems.append(f"bootstrap remnant check: {exc!r}")
        raise AssertionError(f"{len(problems)} teardown step(s) failed: "
                             f"{'; '.join(problems)}") from exc
    else:
        if remaining:
            problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError(f"{len(problems)} teardown step(s) failed: {'; '.join(problems)}")


def _bootstrap_remnants(ctx, toolkit_stack: str, staging_bucket: str, qualifier: str,
                        account: str) -> list[str]:
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(
            StackName=toolkit_stack)["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {toolkit_stack} ({status})")
    except ClientError as exc:
        if not _stack_missing(exc, toolkit_stack):
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
    repo = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[repo])
        remaining.append(f"ecr repository {repo}")
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
