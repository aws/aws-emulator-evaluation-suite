"""map-maxconcurrency-zero-over-many-items-plateaus-at-an-internal-cap."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-maxconcurrency-zero-over-many-items-plateaus-at-an-internal-cap"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_ITEM_WAIT_S = 20
_FEW_ITEMS = 10
_MANY_ITEMS = 150
_MAP_STATE = "M"

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_sfn_role(ctx) -> str:
    """A Step Functions execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmcrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDenied raised while the
    freshly created role's trust grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmc-")
    definition = {
        "StartAt": _MAP_STATE,
        "States": {
            _MAP_STATE: {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": 0,
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Hold",
                    "States": {"Hold": {"Type": "Wait", "Seconds": _ITEM_WAIT_S, "End": True}},
                },
                "End": True,
            }
        },
    }
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start(ctx, sm_arn: str, items: list) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"items": items})
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


_ITERATION_ENDED = ("MapIterationSucceeded", "MapIterationFailed", "MapIterationAborted")


def _in_flight_count(ctx, exec_arn: str) -> int:
    """How many Map iterations this execution's history shows as running right now: the
    MapIterationStarted events minus the iterations that already succeeded, failed or aborted."""
    sfn = ctx.client("stepfunctions")
    events: list = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    started = sum(1 for e in events if e["type"] == "MapIterationStarted")
    ended = sum(1 for e in events if e["type"] in _ITERATION_ENDED)
    return started - ended


def _poll_until_plateau(probe, *, interval_s=2.0, deadline_s=40.0, stable_reads=2) -> int:
    """Poll ``probe`` until it returns the same positive value ``stable_reads`` times in a
    row, ``interval_s`` apart, and return that plateaued value."""
    deadline = time.monotonic() + deadline_s
    last = None
    stable = 0
    while time.monotonic() < deadline:
        current = probe()
        if current == last and current > 0:
            stable += 1
            if stable >= stable_reads:
                return current
        else:
            stable = 0
        last = current
        time.sleep(interval_s)
    raise AssertionError(f"in-flight iteration count never reached a stable plateau within {deadline_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An inline Map with MaxConcurrency 0 (unbounded) over many items does not start them
    all at once: concurrently running iterations plateau at an internal cap between 40 and
    60, while the same Map over fewer items than that cap runs every one of them at once."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # Positive control: fewer items than the cap all run at once -- the plateau below is a real
    # ceiling, not evidence that this Map silently drops or throttles iterations generally.
    few_exec = _start(ctx, sm_arn, list(range(_FEW_ITEMS)))
    few_count = _poll_until_plateau(lambda: _in_flight_count(ctx, few_exec))
    assert few_count == _FEW_ITEMS, (
        f"with only {_FEW_ITEMS} items (well under the internal cap), MaxConcurrency 0 must "
        f"run every one of them at once; the plateaued in-flight count was {few_count}"
    )

    many_exec = _start(ctx, sm_arn, list(range(_MANY_ITEMS)))
    many_count = _poll_until_plateau(lambda: _in_flight_count(ctx, many_exec))
    assert 40 <= many_count <= 60, (
        f"with {_MANY_ITEMS} items and MaxConcurrency 0, concurrently running iterations must "
        f"plateau between 40 and 60 (the service's internal concurrency cap); the plateaued "
        f"in-flight count was {many_count}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
