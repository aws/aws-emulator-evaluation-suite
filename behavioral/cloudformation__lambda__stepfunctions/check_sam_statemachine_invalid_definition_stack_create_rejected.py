"""sam-statemachine-invalid-definition-stack-create-rejected."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "sam-statemachine-invalid-definition-stack-create-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "stepfunctions"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_statemachine_invalid_definition"
_CONTROL_PROJECT = "sam_statemachine_invoke"
_TEMPLATE_FILE = ".aws-sam/build/template.yaml"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)
_DEADLINE_S = 600.0
_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
            "DELETE_COMPLETE", "DELETE_FAILED"}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """`sam deploy` of an AWS::Serverless::StateMachine whose Definition omits StartAt and States
    rolls back with Step Functions' exact schema error and no state machine; a complete
    Definition deploys.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-sfnbad-")
    stack = ctx.unique_name("sim2real-sam-sfnbad-")
    sm_name = ctx.unique_name("sim2real-sam-sfnbad-")
    work = _workdir(ctx, _PROJECT)

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, ["build", "--region", ctx.region]), "build")
    # `sam deploy` exits non-zero on a rolled-back stack; the stack's own terminal status below is
    # the graded outcome, not the CLI's exit code.
    _sam(ctx, work, _deploy_args(ctx, stack, {"FunctionName": fn, "StateMachineName": sm_name}))

    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    status = _poll(lambda: _status(cfn, stack_id), lambda s: s in _TERMINAL,
                   timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} terminal")
    assert status == "ROLLBACK_COMPLETE", (
        f"a stack whose state machine Definition is missing StartAt/States must end "
        f"ROLLBACK_COMPLETE; got {status!r}: {_failures(cfn, stack_id)!r}"
    )

    reason = _resource_failure_reason(cfn, stack_id, "Machine")
    match = _REASON.match(reason)
    assert match is not None, f"Machine's CREATE_FAILED reason is not a handler message: {reason!r}"
    got = (match["message"], match["service"], match["status"], match["handler"])
    want = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: These fields are required: "
        "[States, StartAt] at /'",
        "Sfn",
        "400",
        "InvalidRequest",
    )
    assert got == want, f"Machine's CREATE_FAILED reason: expected {want!r}, got {got!r}"
    roles = _stack_roles(cfn, stack_id)

    sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{sm_name}"
    gone = _absent(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert gone == ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{sm_arn}'"), (
        f"the rejected definition must never bring the state machine into existence; "
        f"DescribeStateMachine on {sm_arn!r} returned {gone!r}"
    )

    _delete_stack_named(cfn, stack)

    gone_fn = _absent(lambda: lam.get_function(FunctionName=fn))
    assert gone_fn == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}",
    ), f"GetFunction after the in-band delete must name the function's own ARN; got {gone_fn!r}"
    _assert_roles_gone(ctx.client("iam"), roles)

    # Positive control: the same function with a complete Definition deploys through SAM.
    ok_fn = ctx.unique_name("sim2real-sam-sfnok-")
    ok_stack = ctx.unique_name("sim2real-sam-sfnok-")
    ok_sm = ctx.unique_name("sim2real-sam-sfnok-")
    ok_work = _workdir(ctx, _CONTROL_PROJECT)
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, ok_stack))
    built = _sam(ctx, ok_work, ["build", "--region", ctx.region])
    assert built.returncode == 0, f"`sam build` of the control exited {built.returncode}"
    deployed = _sam(ctx, ok_work, _deploy_args(ctx, ok_stack, {"FunctionName": ok_fn,
                                                                 "StateMachineName": ok_sm}))
    assert deployed.returncode == 0, (
        f"`sam deploy` of the control exited {deployed.returncode}: "
        f"{(deployed.stdout + deployed.stderr)[-1500:]!r}"
    )
    ok_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{ok_sm}"
    ok_status = sfn.describe_state_machine(stateMachineArn=ok_arn)["status"]
    assert ok_status == "ACTIVE", f"the control state machine is {ok_status!r}, expected ACTIVE"
    ok_roles = _stack_roles(cfn, ok_stack)
    _delete_stack_named(cfn, ok_stack)
    gone = _absent(lambda: sfn.describe_state_machine(stateMachineArn=ok_arn))
    assert gone == ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{ok_arn}'"), (
        f"DescribeStateMachine on the control after its delete: {gone!r}"
    )
    _assert_roles_gone(ctx.client("iam"), ok_roles)


def _resource_failure_reason(cfn, stack_id: str, logical_id: str) -> str:
    """The CREATE_FAILED ResourceStatusReason for ``logical_id``; asserts there is exactly one."""
    hits = [e for e in _events(cfn, stack_id)
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(hits) == 1, (
        f"expected exactly one CREATE_FAILED event for {logical_id!r}, got {hits!r}"
    )
    return hits[0].get("ResourceStatusReason") or ""


def _events(cfn, stack_id: str) -> list:
    out: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _absent(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in _events(cfn, stack_id)
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack `sam deploy` created under `name`, if it exists, and wait for DELETE_COMPLETE."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run(
        [sam, *args], cwd=cwd, env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
        capture_output=True, text=True, timeout=timeout_s,
    )


def _ok(result, what: str) -> None:
    """Assert a SAM CLI run exited 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}"
    )


def _deploy_args(ctx, stack: str, params: dict) -> list:
    """`sam deploy` of the built template; InlineCode needs no packaging bucket."""
    overrides = [f"{k}={v}" for k, v in params.items()]
    return [
        "deploy", "--template-file", _TEMPLATE_FILE, "--stack-name", stack,
        "--capabilities", *_CAPS, "--region", ctx.region,
        "--no-confirm-changeset", "--no-progressbar",
        "--parameter-overrides", *overrides,
        "--tags", f"sim2real={CHECK}",
    ]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
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
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
