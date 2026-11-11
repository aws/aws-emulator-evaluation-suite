"""map-maxconcurrency-one-serialises-iterations-against-an-unbounded-twin."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-maxconcurrency-one-serialises-iterations-against-an-unbounded-twin"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_ITEMS = 6
_WAIT_SECONDS = 3
_MAP_STATE = "Fan"

# Serial: 6 iterations x 3s = 18s. Allow 10% of measurement slop downward.
_SERIAL_FLOOR_S = _ITEMS * _WAIT_SECONDS * 0.9
# Concurrent: one 3s wait plus per-iteration scheduling. Anything at or under this is
# unambiguously overlapping rather than serial.
_PARALLEL_CEILING_S = 10.0


# timing:real-time — workflow: 3 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Map MaxConcurrency=1 really serialises iterations: the same Map takes >= N*W with
    MaxConcurrency=1 and ~W with MaxConcurrency=N, measured from history timestamps."""
    _role_name, role_arn = _create_sfn_role(ctx)

    # Twin state machines from ONE definition template, differing ONLY in MaxConcurrency,
    # executed in the same instant so neither arm can be explained by ambient load.
    serial_arn = _create_state_machine(ctx, role_arn, _definition(max_concurrency=1))
    parallel_arn = _create_state_machine(
        ctx, role_arn, _definition(max_concurrency=_ITEMS)
    )

    payload = {"items": list(range(_ITEMS))}
    serial_exec = _start(ctx, serial_arn, payload)
    parallel_exec = _start(ctx, parallel_arn, payload)

    serial_desc = _wait_terminal(ctx, serial_exec, timeout_s=180.0)
    parallel_desc = _wait_terminal(ctx, parallel_exec, timeout_s=180.0)

    for label, desc in (("serial", serial_desc), ("concurrent", parallel_desc)):
        assert desc["status"] == "SUCCEEDED", (
            f"the {label} arm must SUCCEED before its duration means anything; got "
            f"{desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        output = json.loads(desc["output"])
        assert output == list(range(_ITEMS)), (
            f"the {label} arm's Map must return all {_ITEMS} results in ITEM order "
            f"regardless of completion order; expected {list(range(_ITEMS))}, got {output!r}"
        )

    serial_s = _map_state_duration(ctx, serial_exec)
    parallel_s = _map_state_duration(ctx, parallel_exec)

    # Leg 1 — MaxConcurrency=1 must actually withhold concurrency.
    assert serial_s >= _SERIAL_FLOOR_S, (
        f"a Map with MaxConcurrency=1 over {_ITEMS} items each waiting {_WAIT_SECONDS}s "
        f"must take at least {_SERIAL_FLOOR_S:.1f}s inside the {_MAP_STATE} state; it took "
        f"{serial_s:.2f}s, so the iterations overlapped and MaxConcurrency was ignored"
    )

    # Leg 2 — the twin proves the slowness above is the limit, not the harness. Without
    # this leg a target that simply serialises every Map would score green.
    assert parallel_s <= _PARALLEL_CEILING_S, (
        f"a Map with MaxConcurrency={_ITEMS} over {_ITEMS} items each waiting "
        f"{_WAIT_SECONDS}s must overlap them and finish inside "
        f"{_PARALLEL_CEILING_S:.1f}s; it took {parallel_s:.2f}s, so it serialised anyway"
    )

    # Leg 3 — the two arms must be separated by roughly the withheld parallelism.
    gap = serial_s - parallel_s
    assert gap >= (_ITEMS - 1) * _WAIT_SECONDS * 0.7, (
        f"the MaxConcurrency=1 arm must be slower than the MaxConcurrency={_ITEMS} arm by "
        f"roughly the {_ITEMS - 1} serialised waits "
        f"(>= {(_ITEMS - 1) * _WAIT_SECONDS * 0.7:.1f}s); the measured difference was "
        f"{gap:.2f}s (serial {serial_s:.2f}s vs concurrent {parallel_s:.2f}s)"
    )

    # Leg 4 — the serial arm's iterations must not merely be slow, they must not overlap.
    # Consecutive iterations' start events must be at least one Wait apart.
    starts = _iteration_start_timestamps(ctx, serial_exec)
    assert len(starts) == _ITEMS, (
        f"the serial arm must record one iteration start per item; expected {_ITEMS}, got "
        f"{len(starts)}"
    )
    tightest = min(
        (b - a).total_seconds() for a, b in zip(starts, starts[1:])
    )
    assert tightest >= _WAIT_SECONDS * 0.8, (
        f"with MaxConcurrency=1 no two iterations may be in flight together, so "
        f"consecutive iteration starts must be at least ~{_WAIT_SECONDS}s apart; the "
        f"closest pair was {tightest:.2f}s apart"
    )

    parallel_starts = _iteration_start_timestamps(ctx, parallel_exec)
    assert len(parallel_starts) == _ITEMS, (
        f"the concurrent arm must also record one iteration start per item; expected "
        f"{_ITEMS}, got {len(parallel_starts)}"
    )
    parallel_spread = (parallel_starts[-1] - parallel_starts[0]).total_seconds()
    assert parallel_spread < _WAIT_SECONDS, (
        f"with MaxConcurrency={_ITEMS} all {_ITEMS} iterations must start within one "
        f"{_WAIT_SECONDS}s Wait of each other; they were spread over "
        f"{parallel_spread:.2f}s"
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


def _definition(*, max_concurrency: int) -> str:
    """The SAME Map over the SAME items with the SAME per-item Wait. MaxConcurrency is
    the only difference between the two arms."""
    return json.dumps(
        {
            "Comment": "inline Map whose per-item Wait makes concurrency observable",
            "StartAt": _MAP_STATE,
            "States": {
                _MAP_STATE: {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "MaxConcurrency": max_concurrency,
                    "Iterator": {
                        "StartAt": "Hold",
                        "States": {
                            "Hold": {
                                "Type": "Wait",
                                "Seconds": _WAIT_SECONDS,
                                "Next": "Echo",
                            },
                            "Echo": {"Type": "Pass", "End": True},
                        },
                    },
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmap-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: inline Map concurrency",
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
    name = ctx.unique_name("sim2real-behav-sfnmap-")
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


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
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
        f"execution {exec_arn} still RUNNING after {timeout_s}s; even fully serialised "
        f"this Map is {_ITEMS} x {_WAIT_SECONDS}s. Last: {last!r}"
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


def _map_state_duration(ctx, exec_arn: str) -> float:
    """Seconds between the Map state being entered and exited, read from the history's
    own timestamps rather than from the harness clock."""
    events = _history(ctx, exec_arn)
    entered = [
        e
        for e in events
        if e.get("stateEnteredEventDetails", {}).get("name") == _MAP_STATE
    ]
    exited = [
        e
        for e in events
        if e.get("stateExitedEventDetails", {}).get("name") == _MAP_STATE
    ]
    assert len(entered) == 1 and len(exited) == 1, (
        f"history must record the {_MAP_STATE} Map state entered exactly once and exited "
        f"exactly once; got {len(entered)} entered and {len(exited)} exited out of "
        f"{[e['type'] for e in events]}"
    )
    return (exited[0]["timestamp"] - entered[0]["timestamp"]).total_seconds()


def _iteration_start_timestamps(ctx, exec_arn: str) -> list:
    """Ascending timestamps of each Map iteration's start event."""
    events = _history(ctx, exec_arn)
    starts = [e["timestamp"] for e in events if e["type"] == "MapIterationStarted"]
    assert starts, (
        "history must record MapIterationStarted events for an inline Map; the types "
        f"present were {sorted({e['type'] for e in events})}"
    )
    return sorted(starts)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
