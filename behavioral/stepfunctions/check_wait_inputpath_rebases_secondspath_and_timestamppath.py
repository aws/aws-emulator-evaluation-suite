"""wait-inputpath-rebases-secondspath-and-timestamppath."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-inputpath-rebases-secondspath-and-timestamppath"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_EXPECTED_ERROR = "States.Runtime"
_SECONDS_WAIT = "WaitSeconds"
_TIMESTAMP_WAIT = "WaitTimestamp"

_DEFINITION = {
    "StartAt": "Route",
    "States": {
        "Route": {
            "Type": "Choice",
            "Choices": [
                {"Variable": "$.mode", "StringEquals": "seconds", "Next": _SECONDS_WAIT},
                {"Variable": "$.mode", "StringEquals": "timestamp", "Next": _TIMESTAMP_WAIT},
            ],
        },
        _SECONDS_WAIT: {
            "Type": "Wait",
            "InputPath": "$.wrapped",
            "SecondsPath": "$.seconds",
            "Next": "Done",
        },
        _TIMESTAMP_WAIT: {
            "Type": "Wait",
            "InputPath": "$.wrapped",
            "TimestampPath": "$.timestamp",
            "Next": "Done",
        },
        "Done": {"Type": "Pass", "Result": "released", "End": True},
    },
}


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A Wait's InputPath rebases where SecondsPath/TimestampPath look: both resolve
    against the InputPath-filtered input, not the state's raw input, so a value absent
    from the filtered input fails with States.Runtime naming it by its own exact cause.
    """
    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: SecondsPath resolves against the InputPath-filtered input, ----
    # --- not the raw one -------------------------------------------------------------------
    # Raw top-level "seconds" is a value large enough that this check's own bounded poll
    # would never see it finish; InputPath narrows the input to "wrapped" first, so
    # SecondsPath="$.seconds" finds the SMALL value inside "wrapped" instead.
    ok = _run(ctx, sm_arn, {
        "mode": "seconds",
        "seconds": 9999,
        "wrapped": {"seconds": 1},
    })
    assert ok["status"] == "SUCCEEDED", (
        f"a SecondsPath that resolves inside the InputPath-filtered input must SUCCEED; got "
        f"{ok['status']!r} error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"]) == "released", (
        f"the succeeding run's output must be the Pass result; got {ok.get('output')!r}"
    )
    entered = _entered(_history(ctx, ok["executionArn"]))
    assert entered == ["Route", _SECONDS_WAIT, "Done"], (
        f"the succeeding run must pass through {_SECONDS_WAIT} then Done; entered {entered!r}"
    )

    # --- Negative: SecondsPath, present at raw top level, absent from the filtered input --
    seconds_bad = _run(ctx, sm_arn, {
        "mode": "seconds",
        "seconds": 5,
        "wrapped": {"other": "x"},
    })
    assert seconds_bad["status"] == "FAILED", (
        f"a SecondsPath absent from the InputPath-filtered input must FAIL the execution "
        f"even though the raw input carries 'seconds'; got {seconds_bad['status']!r} "
        f"output={seconds_bad.get('output')!r}"
    )
    assert seconds_bad.get("error") == _EXPECTED_ERROR, (
        f"expected error {_EXPECTED_ERROR!r}, got {seconds_bad.get('error')!r} "
        f"cause={seconds_bad.get('cause')!r}"
    )
    seconds_events = _history(ctx, seconds_bad["executionArn"])
    seconds_entered_id = _entered_event_id(seconds_events, _SECONDS_WAIT)
    assert seconds_bad.get("cause") == (
        f"An error occurred while executing the state '{_SECONDS_WAIT}' (entered at the "
        f"event id #{seconds_entered_id}). The SecondsPath parameter does not reference an "
        f"input value: $.seconds"
    ), f"unexpected cause: {seconds_bad.get('cause')!r}"
    seconds_entered = _entered(seconds_events)
    assert seconds_entered == ["Route", _SECONDS_WAIT], (
        f"a failed Wait must never reach Done; entered {seconds_entered!r}"
    )

    # --- Negative: TimestampPath, present at raw top level, absent from the filtered input
    timestamp_bad = _run(ctx, sm_arn, {
        "mode": "timestamp",
        "timestamp": "2030-01-01T00:00:00Z",
        "wrapped": {"other": "y"},
    })
    assert timestamp_bad["status"] == "FAILED", (
        f"a TimestampPath absent from the InputPath-filtered input must FAIL the execution "
        f"even though the raw input carries 'timestamp'; got {timestamp_bad['status']!r} "
        f"output={timestamp_bad.get('output')!r}"
    )
    assert timestamp_bad.get("error") == _EXPECTED_ERROR, (
        f"expected error {_EXPECTED_ERROR!r}, got {timestamp_bad.get('error')!r} "
        f"cause={timestamp_bad.get('cause')!r}"
    )
    timestamp_events = _history(ctx, timestamp_bad["executionArn"])
    timestamp_entered_id = _entered_event_id(timestamp_events, _TIMESTAMP_WAIT)
    assert timestamp_bad.get("cause") == (
        f"An error occurred while executing the state '{_TIMESTAMP_WAIT}' (entered at the "
        f"event id #{timestamp_entered_id}). The TimestampPath parameter does not reference "
        f"an input value: $.timestamp"
    ), f"unexpected cause: {timestamp_bad.get('cause')!r}"
    timestamp_entered = _entered(timestamp_events)
    assert timestamp_entered == ["Route", _TIMESTAMP_WAIT], (
        f"a failed Wait must never reach Done; entered {timestamp_entered!r}"
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
    """A role Step Functions can assume. A Choice/Wait/Pass machine calls no other service,
    so it needs no permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnwip-role-")
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
    name = ctx.unique_name("sim2real-behav-sfnwip-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(_DEFINITION),
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


def _run(ctx, sm_arn: str, payload: dict, *, timeout_s: float = 90.0) -> dict:
    """Start an execution and poll DescribeExecution every 2s to a terminal status."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
    )["executionArn"]

    def _stop_if_running():
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)

    ctx.on_cleanup(_stop_if_running)
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
