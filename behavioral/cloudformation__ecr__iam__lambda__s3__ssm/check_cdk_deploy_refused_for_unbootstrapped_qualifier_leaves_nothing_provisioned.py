"""cdk-deploy-refused-for-unbootstrapped-qualifier-leaves-nothing-provisioned."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-refused-for-unbootstrapped-qualifier-leaves-nothing-provisioned"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "lambda", "s3", "ssm"]

_APP = "cdk_fn_bootstrap_asset"
_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_BOOTSTRAP_ERROR = "Has the environment been bootstrapped?"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deploying an asset-bearing app under a never-bootstrapped qualifier is refused before any
    change set, naming its own SSM parameter, and leaves no stack or Lambda function behind; once
    bootstrapped the same app deploys, runs and is destroyed.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    lam = ctx.client("lambda")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    app_stack = ctx.unique_name("sim2real-cdkneg-")
    version_parameter = f"/cdk-bootstrap/{qualifier}/version"

    work = _stage_app(ctx, _APP)

    state: dict[str, Any] = {"bootstrapped": False, "function_name": None}
    ctx.on_cleanup(lambda: _teardown(ctx, app_stack, toolkit_stack, state))

    # The qualifier really is a clean slate; otherwise the refusal below proves nothing.
    unbootstrapped = _client_error(lambda: ssm.get_parameter(Name=version_parameter))
    assert unbootstrapped.response["Error"]["Code"] == "ParameterNotFound", (
        f"GetParameter on {version_parameter!r} succeeded, so this qualifier IS bootstrapped "
        f"and the negative arm below would prove nothing"
    )
    assert unbootstrapped.response["Error"]["Message"] == "", (
        unbootstrapped.response["Error"]["Message"]
    )

    context = {
        "account": account, "region": ctx.region,
        "stack_name": app_stack, "qualifier": qualifier,
    }
    rc, output = _cdk(ctx, work, ["deploy", app_stack, "--require-approval", "never"], context,
                      timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk deploy` exited {rc} against the unbootstrapped qualifier {qualifier!r}; the app "
        f"carries a real file asset, so publishing it must be refused with exit 1. Output tail: "
        f"{output[-1200:]!r}"
    )
    assert _BOOTSTRAP_ERROR in output, (
        f"`cdk deploy` failed but not with the bootstrap error; expected {_BOOTSTRAP_ERROR!r} "
        f"in the output. Output tail: {output[-1200:]!r}"
    )
    assert version_parameter in output, (
        f"the refusal did not name this qualifier's own parameter {version_parameter!r}. "
        f"Output tail: {output[-1200:]!r}"
    )

    # What the refused deploy would have created: the stack (never even as a change set, which
    # leaves a REVIEW_IN_PROGRESS or deleted summary behind) and the function it declares.
    _assert_stack_absent(ctx, app_stack)
    summaries = [
        f"{st['StackName']} {st['StackStatus']}"
        for page in cfn.get_paginator("list_stacks").paginate()
        for st in page["StackSummaries"]
        if st["StackName"] == app_stack
    ]
    assert summaries == [], (
        f"ListStacks reports {summaries!r} for {app_stack!r}; a deploy refused for a missing "
        f"bootstrap must never reach CreateChangeSet"
    )
    functions = [
        f["FunctionName"]
        for page in lam.get_paginator("list_functions").paginate()
        for f in page["Functions"]
        if f["FunctionName"].startswith(app_stack)
    ]
    assert functions == [], (
        f"Lambda carries function(s) {functions!r} named from stack {app_stack!r} after a "
        f"refused deploy"
    )

    # Positive control: bootstrap the SAME qualifier and redeploy the SAME app; it now works.
    state["bootstrapped"] = True
    _bootstrap(ctx, account, qualifier, toolkit_stack)
    _cdk(ctx, work, ["deploy", app_stack, "--require-approval", "never"], context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    described = cfn.describe_stacks(StackName=app_stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {app_stack!r} is {described['StackStatus']!r} after bootstrapping {qualifier!r}, "
        f"expected CREATE_COMPLETE — the qualifier's missing bootstrap was not the only cause"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}
    function_name = outputs["FunctionName"]
    state["function_name"] = function_name

    marker = ctx.unique_name("marker-")
    response = lam.invoke(FunctionName=function_name,
                          Payload=json.dumps({"marker": marker}).encode())
    raw_payload = response["Payload"].read()
    assert "FunctionError" not in response, (
        f"Invoke on {function_name!r} reported FunctionError "
        f"{response.get('FunctionError')!r}: {raw_payload.decode()!r}"
    )
    payload = json.loads(raw_payload.decode())
    assert payload == {"echo": marker}, (
        f"Invoke on {function_name!r} returned {payload!r}, expected an echo of {marker!r}"
    )

    # The in-band destroy removes the stack, its function and the function's execution role.
    roles = sorted(
        r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=app_stack)["StackResources"]
        if r["ResourceType"] == "AWS::IAM::Role"
    )
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"
    _cdk(ctx, work, ["destroy", app_stack, "--force"], context,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    _assert_stack_absent(ctx, app_stack)
    gone_fn = _client_error(lambda: lam.get_function(FunctionName=function_name))
    assert gone_fn.response["Error"]["Code"] == "ResourceNotFoundException", (
        gone_fn.response["Error"]
    )
    assert gone_fn.response["Error"]["Message"] == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{account}:function:{function_name}"
    ), gone_fn.response["Error"]["Message"]
    gone_role = _client_error(lambda: iam.get_role(RoleName=roles[0]))
    assert gone_role.response["Error"]["Code"] == "NoSuchEntity", gone_role.response["Error"]
    assert gone_role.response["Error"]["Message"] == (
        f"The role with name {roles[0]} cannot be found."
    ), gone_role.response["Error"]["Message"]


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"call succeeded but was expected to be refused: {result!r}")


def _assert_stack_absent(ctx, stack: str) -> None:
    """DescribeStacks reports the stack absent with ValidationError and the exact message."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the absent stack {stack!r} returned error code {code!r}, "
        f"expected 'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on {stack!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        # AWS_MANAGED_KEY encrypts the staging bucket with the AWS-managed key: no CMK to delete.
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--tags", f"sim2real={CHECK}",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered invocation log can flush and recreate the group after `delete_function`.
    """
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
                    f"log group {name!r} still present after {budget_s}s of deletes; "
                    f"{absent} clean read(s)"
                )
            time.sleep(interval_s)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket (StagingBucket has Retain)."""
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


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float) -> None:
    """Delete by name, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    try:
        cfn.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


def _toolkit_physical_ids(cfn, toolkit_stack: str) -> dict[str, str]:
    """logical id -> PhysicalResourceId for every resource the toolkit stack created."""
    pages = cfn.get_paginator("list_stack_resources").paginate(StackName=toolkit_stack)
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for page in pages
        for r in page["StackResourceSummaries"]
    }


def _teardown(ctx, app_stack: str, toolkit_stack: str, state: dict) -> None:
    """Delete the app stack (if ever created), reap its Lambda's log group, empty the
    toolkit's Retain-policy staging bucket, then the toolkit stack — only what the control
    arm actually built; raises naming whatever is still there.
    """
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []

    app_steps: list[tuple[str, Any]] = [
        (f"app stack {app_stack}",
         lambda: _delete_stack_and_wait(cfn, app_stack, max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in app_steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")

    if not state.get("bootstrapped"):
        return

    toolkit_steps: list[tuple[str, Any]] = []
    function_name = state.get("function_name")
    if function_name:
        toolkit_steps.append((
            f"log group for {function_name}",
            lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{function_name}"),
        ))
    try:
        physical_ids = _toolkit_physical_ids(cfn, toolkit_stack)
    except ClientError as exc:
        if exc.response["Error"].get("Message") != f"Stack with id {toolkit_stack} does not exist":
            raise AssertionError(
                f"could not read toolkit stack {toolkit_stack!r} resources: {exc!r}"
            ) from exc
        physical_ids = {}  # bootstrap never created the stack, so it created nothing
    bucket = physical_ids.get("StagingBucket")
    if bucket:
        # DeletionPolicy: Retain, so the toolkit stack delete below will not touch it.
        toolkit_steps.append((
            f"staging bucket {bucket}",
            lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket),
        ))
    toolkit_steps.append((
        f"toolkit stack {toolkit_stack}",
        lambda: _delete_stack_and_wait(cfn, toolkit_stack, max(30.0, deadline - time.monotonic())),
    ))
    for label, step in toolkit_steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{label}: {exc!r}")

    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
