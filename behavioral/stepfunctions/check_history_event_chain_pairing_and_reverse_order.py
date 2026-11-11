"""history-event-chain-pairing-and-reverse-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "history-event-chain-pairing-and-reverse-order"
GROUP = 'execution_history'
SERVICES = ['stepfunctions']


def _role_arn(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_role_arn(ctx),
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


def _get_history_events(ctx, exec_arn, *, reverse=False):
    sfn = ctx.client("stepfunctions")
    events = []
    kwargs = {"executionArn": exec_arn, "reverseOrder": reverse}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if "nextToken" not in resp:
            break
        kwargs["nextToken"] = resp["nextToken"]
    return events


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Execution history is a contiguous 1..N, previousEventId-linked chain with each state
    entered and exited once, in causal order, ending in ExecutionSucceeded consistent with
    DescribeExecution; reverseOrder=true returns the exact reverse sequence."""
    definition = {
        "StartAt": "Seed",
        "States": {
            "Seed": {"Type": "Pass", "Result": {"stage": "seeded"}, "Next": "Route"},
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.stage", "StringEquals": "seeded", "Next": "Hold"}],
                "Default": "Fan",
            },
            "Hold": {"Type": "Wait", "Seconds": 1, "Next": "Fan"},
            "Fan": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "B1", "States": {"B1": {"Type": "Pass", "Result": 1, "End": True}}},
                    {"StartAt": "B2", "States": {"B2": {"Type": "Pass", "Result": 2, "End": True}}},
                ],
                "Next": "Done",
            },
            "Done": {"Type": "Succeed"},
        },
    }
    exec_arn = _start_execution(
        ctx, _create_state_machine(ctx, definition), input_data={"trace": "history"}
    )
    desc = _wait_execution_complete(ctx, exec_arn, timeout_s=90)
    assert desc["status"] == "SUCCEEDED", (
        f"execution must succeed, got {desc.get('status')} cause={desc.get('cause')}"
    )

    events = _get_history_events(ctx, exec_arn)
    types = [e["type"] for e in events]
    ids = [e["id"] for e in events]

    # 1. Contiguous ids starting at 1, in ascending order as returned.
    assert ids == list(range(1, len(ids) + 1)), (
        f"history ids must be the contiguous sequence 1..{len(ids)} in ascending order, got {ids} "
        f"for types {types}"
    )

    # 2. previousEventId chain integrity: 0 (the execution root) or an earlier event.
    for e in events:
        prev = e.get("previousEventId")
        assert prev is not None, f"event {e['id']} ({e['type']}) has no previousEventId"
        assert prev == 0 or 0 < prev < e["id"], (
            f"event {e['id']} ({e['type']}) has previousEventId {prev}, which is neither 0 nor an "
            f"earlier event id"
        )

    # 3. Every state entered was exited exactly once, matched by name.
    entered = {}
    exited = {}
    for e in events:
        if e["type"].endswith("StateEntered"):
            nm = e.get("stateEnteredEventDetails", {}).get("name")
            assert nm, f"{e['type']} event {e['id']} carries no stateEnteredEventDetails.name"
            entered[nm] = entered.get(nm, 0) + 1
        elif e["type"].endswith("StateExited"):
            nm = e.get("stateExitedEventDetails", {}).get("name")
            assert nm, f"{e['type']} event {e['id']} carries no stateExitedEventDetails.name"
            exited[nm] = exited.get(nm, 0) + 1
    assert entered == exited, (
        f"every entered state must be exited exactly once; entered={entered} exited={exited}"
    )
    for nm in ("Seed", "Route", "Hold", "Fan", "Done", "B1", "B2"):
        assert entered.get(nm) == 1, (
            f"state {nm!r} should be entered exactly once, entered counts were {entered}"
        )

    # 4. Causal ordering across state types.
    def idx_of_type(t):
        assert t in types, f"history is missing a {t} event; types were {types}"
        return types.index(t)

    def idx_of_state(nm):
        for i, e in enumerate(events):
            if e.get("stateEnteredEventDetails", {}).get("name") == nm:
                return i
        raise AssertionError(f"state {nm!r} was never entered; entered states were {list(entered)}")

    order = [
        ("ExecutionStarted", idx_of_type("ExecutionStarted")),
        ("Seed entered", idx_of_state("Seed")),
        ("Route entered", idx_of_state("Route")),
        ("Hold entered", idx_of_state("Hold")),
        ("Fan entered", idx_of_state("Fan")),
        ("ParallelStateSucceeded", idx_of_type("ParallelStateSucceeded")),
        ("ExecutionSucceeded", idx_of_type("ExecutionSucceeded")),
    ]
    for (name_a, i_a), (name_b, i_b) in zip(order, order[1:]):
        assert i_a < i_b, (
            f"{name_a} (position {i_a}) must precede {name_b} (position {i_b}); types were {types}"
        )

    # 5. ExecutionSucceeded is terminal and agrees with the control-plane view.
    assert types[-1] == "ExecutionSucceeded", (
        f"the last history event must be ExecutionSucceeded, got {types[-1]!r}"
    )
    hist_output = events[-1].get("executionSucceededEventDetails", {}).get("output")
    assert hist_output is not None, (
        f"ExecutionSucceeded must carry executionSucceededEventDetails.output, got {events[-1]!r}"
    )
    assert json.loads(hist_output) == json.loads(desc["output"]), (
        f"history output {hist_output!r} disagrees with DescribeExecution output {desc['output']!r}"
    )
    started = events[0]
    assert started["type"] == "ExecutionStarted" and started["id"] == 1, (
        f"the first history event must be ExecutionStarted with id 1, got "
        f"{started['type']!r}/{started['id']}"
    )
    assert json.loads(
        started["executionStartedEventDetails"]["input"]
    ) == {"trace": "history"}, (
        f"ExecutionStarted must echo the execution input, got "
        f"{started['executionStartedEventDetails'].get('input')!r}"
    )

    # 6. reverseOrder returns the same events in exactly the reverse sequence.
    reversed_ids = [e["id"] for e in _get_history_events(ctx, exec_arn, reverse=True)]
    assert reversed_ids == list(reversed(ids)), (
        f"reverseOrder=true must return {list(reversed(ids))}, got {reversed_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
