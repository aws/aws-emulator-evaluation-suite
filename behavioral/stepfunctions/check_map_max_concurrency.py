"""map-max-concurrency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-max-concurrency"
GROUP = 'map_state'
SERVICES = ['stepfunctions']

ITEM_WAIT_SECONDS = 5
N_ITEMS = 4


def _create_sfn_role(ctx):
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
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
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


def _run_to_completion(ctx, definition, input_data=None, *, timeout_s=30):
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    return _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


def _map_wait_definition(max_concurrency):
    """A Map state whose Iterator only Waits ITEM_WAIT_SECONDS per item. Elapsed wall time
    (from the execution's own startDate/stopDate, not a client-side clock) is the only
    observable that distinguishes "MaxConcurrency serializes iterations" from "MaxConcurrency
    is accepted and ignored" — a functional-only check (SUCCEEDED, N outputs) passes either way.
    """
    state = {
        "Type": "Map",
        "ItemsPath": "$.items",
        "Iterator": {
            "StartAt": "W",
            "States": {
                "W": {"Type": "Wait", "Seconds": ITEM_WAIT_SECONDS, "Next": "P"},
                "P": {"Type": "Pass", "End": True},
            },
        },
        "End": True,
    }
    if max_concurrency is not None:
        state["MaxConcurrency"] = max_concurrency
    return {"StartAt": "M", "States": {"M": state}}


def _elapsed_s(result):
    return (result["stopDate"] - result["startDate"]).total_seconds()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """MaxConcurrency=1 actually serializes Map iterations, not merely accepted as a no-op."""
    input_data = {"items": list(range(N_ITEMS))}

    # Positive control: MaxConcurrency omitted (ASL default 0 == unbounded) over the same
    # wiring, so iterations should overlap and the whole Map should take roughly one item's
    # wait, not N of them.
    unbounded = _run_to_completion(ctx, _map_wait_definition(None), input_data, timeout_s=60)
    assert unbounded["status"] == "SUCCEEDED", f"unbounded control did not succeed: {unbounded}"
    unbounded_output = _get_output(unbounded)
    assert len(unbounded_output) == N_ITEMS, (
        f"unbounded control: expected {N_ITEMS} outputs, got {len(unbounded_output)}: {unbounded_output}"
    )
    unbounded_elapsed = _elapsed_s(unbounded)

    # Test: MaxConcurrency=1 must serialize the identical work — each iteration's own Wait
    # must finish before the next iteration starts.
    serial = _run_to_completion(ctx, _map_wait_definition(1), input_data, timeout_s=90)
    assert serial["status"] == "SUCCEEDED", f"MaxConcurrency=1 run did not succeed: {serial}"
    serial_output = _get_output(serial)
    assert len(serial_output) == N_ITEMS, (
        f"MaxConcurrency=1 run: expected {N_ITEMS} outputs, got {len(serial_output)}: {serial_output}"
    )
    serial_elapsed = _elapsed_s(serial)

    min_serial_s = (N_ITEMS - 1) * ITEM_WAIT_SECONDS
    assert serial_elapsed >= min_serial_s, (
        f"MaxConcurrency=1 did not serialize {N_ITEMS}x{ITEM_WAIT_SECONDS}s iterations: "
        f"execution took {serial_elapsed}s, expected >= {min_serial_s}s "
        f"(unbounded control took {unbounded_elapsed}s)"
    )
    assert serial_elapsed >= unbounded_elapsed * 2, (
        f"MaxConcurrency=1 run ({serial_elapsed}s) was not meaningfully slower than the "
        f"unbounded control ({unbounded_elapsed}s) — concurrency does not appear to be capped"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
