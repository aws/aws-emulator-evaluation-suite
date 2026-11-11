"""execution-level-timeoutseconds-yields-timed-out-not-failed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-level-timeoutseconds-yields-timed-out-not-failed"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]

_TIMEOUT_S = 10
_CONTROL_TIMEOUT_S = 900
_HOLD_S = 300
_UPPER_BOUND_S = 60.0


# timing:real-time — workflow: 10 s https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A state machine's own top-level TimeoutSeconds stops a long-running execution with
    status TIMED_OUT (not FAILED), while a twin with a long budget keeps running."""
    _role_name, role_arn = _create_sfn_role(ctx)

    # Twins from the same definition template. The ONLY difference is the top-level
    # TimeoutSeconds, so a target that kills long executions for any other reason — or a
    # target whose Wait state simply does not wait — fails the control leg.
    short_arn = _create_state_machine(ctx, role_arn, _definition(_TIMEOUT_S))
    long_arn = _create_state_machine(ctx, role_arn, _definition(_CONTROL_TIMEOUT_S))

    short_exec = _start(ctx, short_arn)
    long_exec = _start(ctx, long_arn)

    desc = _wait_terminal(ctx, short_exec, timeout_s=_UPPER_BOUND_S + 60.0)

    # --- The timed-out execution ------------------------------------------------------
    assert desc["status"] == "TIMED_OUT", (
        f"an execution that outlives its own top-level TimeoutSeconds={_TIMEOUT_S} must "
        f"report status TIMED_OUT, which is a distinct status from FAILED and ABORTED; got "
        f"{desc['status']!r} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    # Real AWS leaves `error`/`cause` absent for an execution-level TimeoutSeconds
    # timeout (unlike a Task-level timeout, which does report States.Timeout), so
    # the status and terminal history event below are the discriminating legs.

    # Two-sided clock: it must not fire early, and it must not overrun.
    elapsed = (desc["stopDate"] - desc["startDate"]).total_seconds()
    assert elapsed >= _TIMEOUT_S, (
        f"the execution must survive its full TimeoutSeconds={_TIMEOUT_S} budget before "
        f"timing out; it stopped after only {elapsed:.2f}s"
    )
    assert elapsed < _UPPER_BOUND_S, (
        f"the execution must time out promptly after its {_TIMEOUT_S}s budget, well "
        f"inside {_UPPER_BOUND_S}s (the Wait it is sitting in is {_HOLD_S}s long); it "
        f"took {elapsed:.2f}s"
    )

    # --- The twin control, read in the same instant ------------------------------------
    control = ctx.client("stepfunctions").describe_execution(executionArn=long_exec)
    assert control["status"] == "RUNNING", (
        f"the twin with TimeoutSeconds={_CONTROL_TIMEOUT_S} must still be RUNNING at the "
        f"moment its sibling timed out, otherwise the timeout above proves nothing about "
        f"TimeoutSeconds; the twin was {control['status']!r} error="
        f"{control.get('error')!r} cause={control.get('cause')!r}"
    )

    # --- History: the terminal event type, and where the execution died ----------------
    events = _history(ctx, short_exec)
    types = [e["type"] for e in events]
    assert types[-1] == "ExecutionTimedOut", (
        "the last history event of a timed-out execution must be ExecutionTimedOut, not "
        f"ExecutionFailed or ExecutionAborted; the history was {types}"
    )
    assert "ExecutionFailed" not in types, (
        f"a timeout must not also be recorded as ExecutionFailed; history was {types}"
    )

    entered = [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if "stateEnteredEventDetails" in e
    ]
    exited = [
        e["stateExitedEventDetails"]["name"]
        for e in events
        if "stateExitedEventDetails" in e
    ]
    assert "Hold" in entered, (
        f"the execution must have entered the {_HOLD_S}s Wait state 'Hold' before timing "
        f"out; the states it entered were {entered}"
    )
    assert "Hold" not in exited, (
        "the execution timed out INSIDE the Wait, so 'Hold' must never be exited; the "
        f"states it exited were {exited}"
    )
    assert "AfterHold" not in entered, (
        "the state following the Wait must never be entered by a timed-out execution; the "
        f"states it entered were {entered}"
    )

    # --- Stop the control and prove the two terminal statuses are different ------------
    sfn = ctx.client("stepfunctions")
    sfn.stop_execution(executionArn=long_exec)
    stopped = _wait_terminal(ctx, long_exec, timeout_s=90.0)
    assert stopped["status"] == "ABORTED", (
        "explicitly stopping the twin must produce ABORTED, a third status distinct from "
        f"both TIMED_OUT and FAILED; got {stopped['status']!r}"
    )
    assert stopped["status"] != desc["status"], (
        "an aborted execution and a timed-out execution must not share a status word; "
        f"both reported {stopped['status']!r}"
    )
    stopped_types = [e["type"] for e in _history(ctx, long_exec)]
    assert stopped_types[-1] == "ExecutionAborted", (
        "the stopped twin's terminal history event must be ExecutionAborted, not "
        f"ExecutionTimedOut; the history was {stopped_types}"
    )


_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _definition(timeout_seconds: int) -> str:
    """A Wait far longer than either budget, so the only thing that can stop the short
    arm is its own top-level TimeoutSeconds."""
    return json.dumps(
        {
            "Comment": "execution-level timeout over a long Wait",
            "StartAt": "Hold",
            "TimeoutSeconds": timeout_seconds,
            "States": {
                "Hold": {"Type": "Wait", "Seconds": _HOLD_S, "Next": "AfterHold"},
                "AfterHold": {"Type": "Pass", "Result": {"reached": True}, "End": True},
            },
        }
    )


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfntmo-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: execution-level TimeoutSeconds",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["states:DescribeStateMachine"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while
    the freshly created role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfntmo-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _start(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"probe": CHECK})
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(
        f"execution {exec_arn} was still RUNNING after {timeout_s}s, so nothing enforced "
        f"its budget. Last: {last!r}"
    )


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    events: list[dict] = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return sorted(events, key=lambda e: e["id"])
        kwargs["nextToken"] = token


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
