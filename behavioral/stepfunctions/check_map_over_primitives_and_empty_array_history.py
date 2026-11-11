"""map-over-primitives-and-empty-array-history."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-over-primitives-and-empty-array-history"
GROUP = "map_state"
SERVICES = ["stepfunctions"]


def _trust_policy() -> str:
    return json.dumps(
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


def _definition() -> str:
    return json.dumps(
        {
            "Comment": "an inline Map over $.items that echoes each item unchanged",
            "StartAt": "MapState",
            "States": {
                "MapState": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "Echo",
                        "States": {"Echo": {"Type": "Pass", "End": True}},
                    },
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmaph-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """A STANDARD state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmaph-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_definition(),
                roleArn=role_arn,
                type="STANDARD",
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
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=STANDARD) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


def _start_execution(ctx, sm_arn: str, items: list) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-exec-")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=name, input=json.dumps({"items": items})
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 120.0) -> dict:
    """Poll DescribeExecution every 2s against a clock deadline until terminal."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _history(ctx, exec_arn: str) -> list:
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return events


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An inline Map over strings and ints, and over an empty array, records a
    MapStateStarted.length matching the item count and exactly that many
    MapIterationStarted/Succeeded events, each carrying an index below that count.
    """
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Non-empty: a mix of strings and ints -----------------------------------------
    items = ["alpha", 7, "charlie", 99]
    exec_arn = _start_execution(ctx, sm_arn, items)
    desc = _wait_terminal(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"Map over strings and ints must succeed, got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    output = json.loads(desc["output"])
    assert output == items, (
        f"a Map of Pass-through Echo states must return each item unchanged and in order; "
        f"expected {items!r}, got {output!r}"
    )

    events = _history(ctx, exec_arn)
    started_lengths = [
        e["mapStateStartedEventDetails"]["length"]
        for e in events
        if e["type"] == "MapStateStarted"
    ]
    assert started_lengths == [len(items)], (
        f"expected one MapStateStarted with length {len(items)}, got {started_lengths!r}"
    )

    iter_started = [
        e["mapIterationStartedEventDetails"]["index"]
        for e in events
        if e["type"] == "MapIterationStarted"
    ]
    assert len(iter_started) == len(items), (
        f"expected {len(items)} MapIterationStarted events, got {len(iter_started)}: "
        f"{iter_started!r}"
    )
    assert sorted(iter_started) == list(range(len(items))), (
        f"MapIterationStarted indexes must cover 0..{len(items) - 1} exactly once, "
        f"got {sorted(iter_started)!r}"
    )

    iter_succeeded = [
        e["mapIterationSucceededEventDetails"]["index"]
        for e in events
        if e["type"] == "MapIterationSucceeded"
    ]
    assert len(iter_succeeded) == len(items), (
        f"expected {len(items)} MapIterationSucceeded events, got {len(iter_succeeded)}: "
        f"{iter_succeeded!r}"
    )
    assert sorted(iter_succeeded) == list(range(len(items))), (
        f"MapIterationSucceeded indexes must cover 0..{len(items) - 1} exactly once, "
        f"got {sorted(iter_succeeded)!r}"
    )
    assert all(0 <= i < len(items) for i in iter_started + iter_succeeded), (
        f"every MapIteration index must be below the array length {len(items)}, "
        f"got started={iter_started!r} succeeded={iter_succeeded!r}"
    )

    # --- The empty array: zero items, zero iterations, output stays [] ----------------
    empty_exec_arn = _start_execution(ctx, sm_arn, [])
    empty_desc = _wait_terminal(ctx, empty_exec_arn)
    assert empty_desc["status"] == "SUCCEEDED", (
        f"a Map over an empty array must succeed, got {empty_desc['status']!r} "
        f"error={empty_desc.get('error')!r} cause={empty_desc.get('cause')!r}"
    )
    empty_output = json.loads(empty_desc["output"])
    assert empty_output == [], f"a Map over an empty array must output [], got {empty_output!r}"

    empty_events = _history(ctx, empty_exec_arn)
    empty_started_lengths = [
        e["mapStateStartedEventDetails"]["length"]
        for e in empty_events
        if e["type"] == "MapStateStarted"
    ]
    assert empty_started_lengths == [0], (
        f"expected one MapStateStarted with length 0, got {empty_started_lengths!r}"
    )
    empty_iterations = [
        e["type"] for e in empty_events if e["type"].startswith("MapIteration")
    ]
    assert empty_iterations == [], (
        f"a Map over an empty array must start no iterations, got {empty_iterations!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
