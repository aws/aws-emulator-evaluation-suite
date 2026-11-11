"""redrive-execution-succeeded-not-redrivable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-succeeded-not-redrivable"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


_SFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx):
    """An execution role this check creates, trusted by states.amazonaws.com."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_SFN_TRUST),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _asl_fail():
    state = {"Type": "Fail", "Error": "BoomAlways", "Cause": "deliberate"}
    return {"Comment": "behavioral-fail", "StartAt": "F", "States": {"F": state}}


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _wait_for_status(ctx, exec_arn, statuses, *, timeout_s=30, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} status not in {statuses} within {timeout_s}s: {last!r}")


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — RedriveExecution accepted a "
        "SUCCEEDED execution"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a SUCCEEDED execution (redriveStatus NOT_REDRIVABLE) fails with
    ExecutionNotRedrivable and the exact message and leaves it SUCCEEDED with redriveCount 0, while a
    FAILED execution (REDRIVABLE) redrives in place."""
    sfn = ctx.client("stepfunctions")

    # ---- positive control: redrive on a FAILED execution is accepted ----
    fail_arn = _create_state_machine(ctx, _asl_fail())
    fail_exec = _start_execution(ctx, fail_arn)
    failed = _wait_execution_complete(ctx, fail_exec)
    assert failed["status"] == "FAILED", f"expected FAILED before redrive, got {failed}"
    assert failed.get("redriveStatus") == "REDRIVABLE", (
        f"expected a fresh FAILED execution to report redriveStatus=REDRIVABLE, got {failed!r}"
    )
    sfn.redrive_execution(executionArn=fail_exec)
    redriven = _wait_for_status(ctx, fail_exec, {"RUNNING", "PENDING_REDRIVE"})
    assert redriven["executionArn"] == fail_exec, "redrive must resume the SAME execution"

    # ---- break exactly one thing: redrive the same shape of execution, but SUCCEEDED ----
    arn = _create_state_machine(ctx, _asl_pass({"ok": True}))
    exec_arn = _start_execution(ctx, arn)
    result = _wait_execution_complete(ctx, exec_arn)
    assert result["status"] == "SUCCEEDED"
    assert result.get("redriveStatus") == "NOT_REDRIVABLE", (
        f"expected a SUCCEEDED execution to report redriveStatus=NOT_REDRIVABLE, got {result!r}"
    )

    code, message = _error(lambda: sfn.redrive_execution(executionArn=exec_arn))
    assert code == "ExecutionNotRedrivable", f"expected ExecutionNotRedrivable, got {code}"
    expected = f"Execution {exec_arn} invalid for redrive as: Execution is SUCCEEDED and cannot be redriven"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ---- effect absent: an independent read shows the refused redrive changed nothing ----
    after = sfn.describe_execution(executionArn=exec_arn)
    assert after["status"] == "SUCCEEDED", (
        f"expected the SUCCEEDED execution's status to be unchanged by the refused redrive, got {after!r}"
    )
    assert after.get("redriveCount", 0) == 0, (
        f"expected redriveCount to stay 0 after a refused redrive, got {after!r}"
    )
    assert after.get("redriveStatus") == "NOT_REDRIVABLE", (
        f"expected redriveStatus to remain NOT_REDRIVABLE after the refused redrive, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
