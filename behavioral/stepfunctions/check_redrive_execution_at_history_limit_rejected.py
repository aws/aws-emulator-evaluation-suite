"""redrive-execution-at-history-limit-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-at-history-limit-rejected"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]

_N_ITEMS = 3200  # 3 Pass states per item: enough INLINE history events to pass 25,000
_HISTORY_CAUSE = "The execution reached the maximum number of history events (25000)."

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_state_machine(ctx, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn, name=name, definition=json.dumps(definition), roleArn=_create_sfn_role(ctx),
        type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _history_limit_definition():
    return {
        "StartAt": "Fan",
        "States": {"Fan": {
            "Type": "Map",
            "ItemsPath": "$.items",
            "ItemProcessor": {
                "ProcessorConfig": {"Mode": "INLINE"},
                "StartAt": "A",
                "States": {
                    "A": {"Type": "Pass", "Next": "B"},
                    "B": {"Type": "Pass", "Next": "C"},
                    "C": {"Type": "Pass", "End": True},
                },
            },
            "End": True,
        }},
    }


def _fail_definition():
    return {"StartAt": "F", "States": {"F": {"Type": "Fail", "Error": "BoomAlways", "Cause": "deliberate"}}}


def _start_execution(ctx, sm_arn, *, input_data=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn, "name": ctx.unique_name("sim2real-behav-exec-")}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _wait_for_status(ctx, exec_arn, statuses, *, timeout_s, interval_s=2.0):
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
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it succeeded: {result!r}"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on an execution FAILED by exceeding the 25,000-event history limit is
    refused with ExecutionNotRedrivable and the exact message, while an ordinary FAILED
    execution's redrive is accepted."""
    sfn = ctx.client("stepfunctions")

    # ---- positive control: an ordinary FAILED execution is REDRIVABLE and redrives ----
    fail_arn = _create_state_machine(ctx, _fail_definition())
    fail_exec = _start_execution(ctx, fail_arn)
    failed = _wait_terminal(ctx, fail_exec, timeout_s=30)
    assert failed["status"] == "FAILED", f"expected FAILED before redrive, got {failed!r}"
    assert failed.get("redriveStatus") == "REDRIVABLE", (
        f"expected a fresh FAILED execution to report redriveStatus=REDRIVABLE, got {failed!r}"
    )
    sfn.redrive_execution(executionArn=fail_exec)
    redriven = _wait_for_status(ctx, fail_exec, {"RUNNING", "PENDING_REDRIVE", "FAILED"}, timeout_s=30)
    assert redriven["executionArn"] == fail_exec, "redrive must resume the SAME execution"

    # ---- break exactly one thing: an execution FAILED at the 25,000-event history limit ----
    history_arn = _create_state_machine(ctx, _history_limit_definition())
    history_exec = _start_execution(ctx, history_arn, input_data={"items": list(range(_N_ITEMS))})
    history_result = _wait_terminal(ctx, history_exec, timeout_s=280.0)
    assert history_result["status"] == "FAILED", (
        f'the {_N_ITEMS!r}-item INLINE Map execution was {history_result["status"]!r}, expected FAILED'
    )
    assert (history_result.get("error"), history_result.get("cause")) == ("States.Runtime", _HISTORY_CAUSE), (
        f'expected the history-limit failure, got {history_result.get("error")!r} / '
        f'{history_result.get("cause")!r}'
    )
    last_event = sfn.get_execution_history(
        executionArn=history_exec, reverseOrder=True, maxResults=1)["events"][0]
    assert (last_event["id"], last_event["type"]) == (25000, "ExecutionFailed"), (
        f'the history-limited execution\'s final event is #{last_event["id"]!r} '
        f'{last_event["type"]!r}, expected #25000 ExecutionFailed'
    )
    assert history_result.get("redriveStatus") == "NOT_REDRIVABLE", (
        f"expected a history-limited FAILED execution to report redriveStatus=NOT_REDRIVABLE, "
        f"got {history_result!r}"
    )

    code, message = _error(lambda: sfn.redrive_execution(executionArn=history_exec))
    assert code == "ExecutionNotRedrivable", (
        f"expected ExecutionNotRedrivable redriving an execution past the history limit, got {code}"
    )
    expected = (
        f"Execution {history_exec} invalid for redrive as: "
        f"Execution has exceeded the maximum history event limit"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ---- effect absent: an independent read shows the refused redrive changed nothing ----
    after = sfn.describe_execution(executionArn=history_exec)
    assert after["status"] == "FAILED", (
        f"expected the history-limited execution's status to stay FAILED, got {after!r}"
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
