"""deploy-cdk-update-rejected-by-aws-rolls-back-keeping-prior-config."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-update-rejected-by-aws-rolls-back-keeping-prior-config"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_APP = "cdk_env_rollback"
_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
# The exact message AWS Lambda's UpdateFunctionConfiguration returns for a reserved env key,
# as CloudFormation's resource handler relays it: 'Resource handler returned message: "<msg>
# (Service: Lambda, Status Code: 400, Request ID: <uuid>) (SDK Attempt Count: <n>)"
# (RequestToken: <uuid>, HandlerErrorCode: <code>)'. The uuids and attempt count vary per run,
# so each stable part is compared exactly.
_EXPECTED_HANDLER_MESSAGE = (
    'Resource handler returned message: "Lambda was unable to configure your environment '
    "variables because the environment variables you have provided contains reserved keys "
    "that are currently not supported for modification. Reserved keys used in this request: "
    "AWS_REGION"
)
_EXPECTED_SERVICE_AND_STATUS = "Lambda, Status Code: 400"
_EXPECTED_HANDLER_CODE = "InvalidRequest)"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CDK update that changes MARKER and adds the Lambda-reserved key AWS_REGION is refused
    whole: the stack ends at UPDATE_ROLLBACK_COMPLETE with `cdk deploy` exiting non-zero, the
    function keeps its pre-update configuration, and a later valid update still applies.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    stack = ctx.unique_name("sim2real-cdkenvrb-")
    work = _stage_app(ctx, _APP)
    base_context = {"stack_name": stack, "account": account, "region": ctx.region}

    marker1 = ctx.unique_name("m1-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))
    _cdk(ctx, work, ["deploy", "--require-approval", "never"],
         {**base_context, "marker": marker1, "bad": "0"},
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    fn_name = _stack_outputs(ctx, stack)["FunctionName"]
    before_vars = _env(lam, fn_name)
    assert before_vars == {"MARKER": marker1}, (
        f"after the first deploy, function {fn_name!r} has Environment.Variables "
        f"{before_vars!r}, expected only {{'MARKER': {marker1!r}}}"
    )
    before_config = lam.get_function_configuration(FunctionName=fn_name)

    # The update changes MARKER and adds the Lambda-reserved key AWS_REGION; Lambda refuses both.
    marker2 = ctx.unique_name("m2-")
    rc, output = _cdk(ctx, work, ["deploy", "--require-approval", "never"],
                      {**base_context, "marker": marker2, "bad": "1"},
                      timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc != 0, (
        f"`cdk deploy` exited 0 updating Environment.Variables to include the Lambda-reserved "
        f"key AWS_REGION; AWS's UpdateFunctionConfiguration must refuse this. Output tail: "
        f"{output[-800:]!r}"
    )

    left = ctx.time_left()
    rolled_back = _wait_for_terminal_status(
        cfn, stack, timeout_s=_DEPLOY_TIMEOUT_S if left is None else min(_DEPLOY_TIMEOUT_S, left))
    assert rolled_back == "UPDATE_ROLLBACK_COMPLETE", (
        f"stack {stack!r} reached {rolled_back!r} after the refused update, expected "
        f"'UPDATE_ROLLBACK_COMPLETE'"
    )

    reason = _resource_failure_reason(cfn, stack, "Fn")
    handler_message, _, rest = reason.partition(" (Service: ")
    assert handler_message == _EXPECTED_HANDLER_MESSAGE, (
        f"Fn resource's UPDATE_FAILED reason was {reason!r}; expected the handler message "
        f"{_EXPECTED_HANDLER_MESSAGE!r}"
    )
    service_and_status = rest.partition(", Request ID: ")[0]
    assert service_and_status == _EXPECTED_SERVICE_AND_STATUS, (
        f"Fn resource's UPDATE_FAILED reason was {reason!r}; UpdateFunctionConfiguration "
        f"rejects the reserved key with HTTP 400 from the Lambda service"
    )
    handler_code = reason.rpartition(", HandlerErrorCode: ")[2]
    assert handler_code == _EXPECTED_HANDLER_CODE, (
        f"Fn resource's UPDATE_FAILED reason was {reason!r}; the Lambda resource handler "
        f"classifies the rejected update as InvalidRequest"
    )

    after_vars = _env(lam, fn_name)
    assert after_vars == {"MARKER": marker1}, (
        f"after the rolled-back update, function {fn_name!r} has Environment.Variables "
        f"{after_vars!r}; it must keep its PRIOR configuration {{'MARKER': {marker1!r}}}, not "
        f"the rejected update's own values"
    )
    after_config = lam.get_function_configuration(FunctionName=fn_name)
    assert after_config["CodeSha256"] == before_config["CodeSha256"], (
        f"the rejected-and-rolled-back update changed CodeSha256 from "
        f"{before_config['CodeSha256']!r} to {after_config['CodeSha256']!r}"
    )

    # Control: the rolled-back stack is not wedged -- a later valid update still applies.
    marker3 = ctx.unique_name("m3-")
    _cdk(ctx, work, ["deploy", "--require-approval", "never"],
         {**base_context, "marker": marker3, "bad": "0"},
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    final_status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert final_status == "UPDATE_COMPLETE", (
        f"the follow-up good update left the stack at {final_status!r}, expected "
        f"'UPDATE_COMPLETE'"
    )
    final_vars = _env(lam, fn_name)
    assert final_vars == {"MARKER": marker3}, (
        f"after the follow-up good update, function {fn_name!r} has Environment.Variables "
        f"{final_vars!r}, expected {{'MARKER': {marker3!r}}}"
    )


def _env(lam, fn_name: str) -> dict[str, str]:
    """The function's current Environment.Variables, read back independently of the deploy."""
    return dict(lam.get_function_configuration(FunctionName=fn_name)["Environment"]["Variables"])


def _resource_failure_reason(cfn, stack: str, logical_id: str) -> str:
    """The most recent UPDATE_FAILED StackEvent reason for one logical resource."""
    events = [
        e
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    assert events, f"no UPDATE_FAILED event found for logical resource {logical_id!r}"
    latest = max(events, key=lambda e: e["Timestamp"])
    return latest.get("ResourceStatusReason", "")


def _wait_for_terminal_status(cfn, stack: str, *, timeout_s: float, interval_s: float = 5.0) -> str:
    """Poll DescribeStacks until the stack's status is terminal; return it."""
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STATES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack!r} did not reach a terminal state within {timeout_s}s "
                         f"(last status {status!r})")


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present={(source / 'app.py').is_file()}, "
        f"cdk.json present={(source / 'cdk.json').is_file()}"
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


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's own output."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE"), (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE or "
        f"UPDATE_COMPLETE before reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") == "ValidationError"
                    and "does not exist" in str(exc)):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
