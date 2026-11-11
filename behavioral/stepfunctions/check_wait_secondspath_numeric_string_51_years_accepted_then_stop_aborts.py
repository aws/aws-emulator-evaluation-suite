"""wait-secondspath-numeric-string-51-years-accepted-then-stop-aborts."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-secondspath-numeric-string-51-years-accepted-then-stop-aborts"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_WAIT_STATE = "Hold"
# ~51 years in seconds, given as a numeric STRING -- not a JSON number -- in the state input.
_FIFTY_ONE_YEARS_S = "1609437600"

_DEFINITION = json.dumps(
    {
        "Comment": "a SecondsPath value that is a numeric string denoting ~51 years",
        "StartAt": _WAIT_STATE,
        "States": {
            _WAIT_STATE: {"Type": "Wait", "SecondsPath": "$.seconds", "Next": "After"},
            "After": {"Type": "Succeed"},
        },
    }
)


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A Wait's SecondsPath resolving to a numeric string of ~51 years is ACCEPTED, not
    rejected for its type: the execution genuinely parks in the Wait, and StopExecution
    then ends it ABORTED with WaitStateEntered as history's last-but-one event.
    """
    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"seconds": _FIFTY_ONE_YEARS_S})
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))

    # The execution must not be rejected for the string type: it must reach RUNNING with
    # the Wait entered, never FAILED, before we stop it.
    entered_desc = _poll_until(
        lambda: (sfn.describe_execution(executionArn=exec_arn), _history(ctx, exec_arn)),
        lambda pair: "WaitStateEntered" in [e["type"] for e in pair[1]] or pair[0]["status"] != "RUNNING",
        timeout_s=60.0,
        description=f"{exec_arn} entering its Wait state",
    )
    desc, events_before_stop = entered_desc
    assert desc["status"] == "RUNNING", (
        f"a numeric-string SecondsPath of {_FIFTY_ONE_YEARS_S!r} (~51 years) must be "
        f"ACCEPTED and the execution must still be RUNNING, parked in the Wait; got "
        f"{desc['status']!r} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert [e["type"] for e in events_before_stop] == ["ExecutionStarted", "WaitStateEntered"], (
        f"before the stop, history must be exactly ExecutionStarted then WaitStateEntered; "
        f"got {[e['type'] for e in events_before_stop]!r}"
    )

    sfn.stop_execution(
        executionArn=exec_arn, error="OperatorAbort", cause="stopped before the 51-year wait could elapse"
    )
    stopped = _wait_terminal(ctx, exec_arn, timeout_s=60.0)

    assert stopped["status"] == "ABORTED", (
        f"stopping an execution parked in a ~51-year Wait must produce ABORTED; got "
        f"{stopped['status']!r}"
    )
    assert stopped["error"] == "OperatorAbort", (
        f"the stopped execution must carry the caller's own error; got "
        f"{stopped.get('error')!r}"
    )
    assert stopped["cause"] == "stopped before the 51-year wait could elapse", (
        f"the stopped execution must carry the caller's own cause; got "
        f"{stopped.get('cause')!r}"
    )
    assert "output" not in stopped, (
        f"the aborted execution never reached 'After' and must carry no output; got "
        f"{stopped.get('output')!r}"
    )

    events = _history(ctx, exec_arn)
    types = [e["type"] for e in events]
    assert types == ["ExecutionStarted", "WaitStateEntered", "ExecutionAborted"], (
        f"the aborted run's history must be exactly this triple, with WaitStateEntered as "
        f"the last-but-one event; got {types!r}"
    )
    assert "WaitStateExited" not in types, (
        f"the Wait was interrupted by the stop and must never have exited; history {types!r}"
    )
    assert "SucceedStateEntered" not in types, (
        f"the run must never reach 'After'; history {types!r}"
    )


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s. Last: {last!r}")


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    events: list[dict] = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return sorted(events, key=lambda e: e["id"])


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume. A Wait/Succeed machine calls no other service, so
    it needs no permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfn51y-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the
    freshly created role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn51y-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_DEFINITION,
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
            time.sleep(3.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. Last error: {last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
