"""wait-outputpath-is-applied-after-the-wait-completes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-outputpath-is-applied-after-the-wait-completes"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_WAIT_STATE = "Hold"
_SECONDS = 5
_SLACK_S = 15.0
_EXPECTED_ERROR = "States.Runtime"

_DEFINITION = {
    "StartAt": _WAIT_STATE,
    "States": {
        _WAIT_STATE: {
            "Type": "Wait",
            "Seconds": _SECONDS,
            "OutputPath": "$.missing",
            "Next": "After",
        },
        "After": {"Type": "Pass", "End": True},
    },
}


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
    "dp:api", "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """A Wait's OutputPath is applied only once the Wait completes, not validated up front:
    an OutputPath that cannot resolve still pays the full Seconds before the execution
    fails, and the failure happens at the Wait state itself, after it has been entered.
    """
    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    exec_arn = _start(ctx, sm_arn, {"present": "value"})
    desc = _wait_terminal(ctx, exec_arn, timeout_s=_SECONDS + _SLACK_S + 60.0)

    assert desc["status"] == "FAILED", (
        f"an OutputPath that cannot resolve must FAIL the execution; got {desc['status']!r} "
        f"output={desc.get('output')!r}"
    )
    assert desc.get("error") == _EXPECTED_ERROR, (
        f"expected error {_EXPECTED_ERROR!r}, got {desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )

    events = _history(ctx, exec_arn)
    entered_id = _entered_event_id(events, _WAIT_STATE)
    elapsed = _wait_to_close_s(events, "ExecutionFailed")
    assert desc.get("cause") == (
        f"An error occurred while executing the state '{_WAIT_STATE}' (entered at the "
        f"event id #{entered_id}). Invalid path '$.missing' : No results for path: "
        f"$['missing']"
    ), f"unexpected cause: {desc.get('cause')!r}"

    # --- The Wait was actually paused for its full Seconds before OutputPath's failure ---
    # --- surfaced -- an eagerly-validated OutputPath would fail near-instantly instead ---
    assert elapsed >= _SECONDS, (
        f"the execution must pay the full Seconds={_SECONDS} budget before an OutputPath "
        f"failure can surface, proving OutputPath is applied after the wait, not before "
        f"it; it failed after only {elapsed:.2f}s"
    )
    assert elapsed < _SECONDS + _SLACK_S, (
        f"the execution must fail promptly once Seconds={_SECONDS} has elapsed, well "
        f"inside {_SECONDS + _SLACK_S:.0f}s; it took {elapsed:.2f}s"
    )

    entered = _entered(events)
    assert entered == [_WAIT_STATE], (
        f"the failure is attributed to {_WAIT_STATE} itself, which must be entered exactly "
        f"once and nothing else entered; history entered {entered!r}"
    )
    assert "After" not in entered, (
        f"the state after the Wait must never be entered; entered {entered!r}"
    )

    # --- Positive control: the same machine, an OutputPath that DOES resolve, succeeds ---
    # --- after paying the same Seconds budget --------------------------------------------
    ok_arn = _create_state_machine(ctx, role_arn, output_path="$.present")
    ok_exec = _start(ctx, ok_arn, {"present": "value"})
    ok_desc = _wait_terminal(ctx, ok_exec, timeout_s=_SECONDS + _SLACK_S + 60.0)
    assert ok_desc["status"] == "SUCCEEDED", (
        f"the control's OutputPath DOES resolve and must SUCCEED; got {ok_desc['status']!r} "
        f"error={ok_desc.get('error')!r} cause={ok_desc.get('cause')!r}"
    )
    assert json.loads(ok_desc["output"]) == "value", (
        f"the control's output must be the OutputPath-selected value; got "
        f"{ok_desc.get('output')!r}"
    )
    ok_elapsed = _wait_to_close_s(_history(ctx, ok_exec), "ExecutionSucceeded")
    assert ok_elapsed >= _SECONDS, (
        f"the control must also pay the full Seconds={_SECONDS} budget; it finished after "
        f"only {ok_elapsed:.2f}s"
    )


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume. A Wait/Pass machine calls no other service, so it
    needs no permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnwop-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str, *, output_path: str | None = None) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the
    freshly created role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnwop-")
    definition = _DEFINITION
    if output_path is not None:
        definition = json.loads(json.dumps(_DEFINITION))
        definition["States"][_WAIT_STATE]["OutputPath"] = output_path
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
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


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
    )["executionArn"]

    def _stop_if_running():
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)

    ctx.on_cleanup(_stop_if_running)
    return exec_arn


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


def _entered(events: list[dict]) -> list[str]:
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if e["type"].endswith("StateEntered")
    ]


def _wait_to_close_s(events: list[dict], close_type: str) -> float:
    """Seconds from the WaitStateEntered event to the execution's closing event, both read from
    the execution history so the measure is the service's own clock."""
    entered = [e["timestamp"] for e in events if e["type"] == "WaitStateEntered"]
    closed = [e["timestamp"] for e in events if e["type"] == close_type]
    assert len(entered) == 1 and len(closed) == 1, (
        f"expected one WaitStateEntered and one {close_type}; history {[e['type'] for e in events]!r}"
    )
    return (closed[0] - entered[0]).total_seconds()


def _entered_event_id(events: list[dict], state: str) -> int:
    """The history event id of the StateEntered event naming ``state``, visited exactly once."""
    matches = [
        e["id"]
        for e in events
        if e["type"].endswith("StateEntered") and e["stateEnteredEventDetails"]["name"] == state
    ]
    assert len(matches) == 1, f"expected exactly one StateEntered for {state!r}; got {matches!r}"
    return matches[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
