"""deep-sfn-2-sfn-jsonata-map-items-expression-and-item-context."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-map-items-expression-and-item-context"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A JSONata Map iterates the array its `Items` expression computes, not `$states.input` itself,
    with each iteration's context Value/Index and the aggregate `$states.result` joined to the
    MapIterationStarted history events."""
    role_arn = _create_role(ctx)
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Lines",
        "States": {
            "Lines": {
                "Type": "Map",
                "Items": "{% $states.input.orders[qty > 0] %}",
                "ItemSelector": {
                    "sku": "{% $states.context.Map.Item.Value.sku %}",
                    "qty": "{% $states.context.Map.Item.Value.qty %}",
                    "idx": "{% $states.context.Map.Item.Index %}",
                    "rate": "{% $states.input.rate %}",
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Price",
                    "States": {
                        "Price": {
                            "Type": "Pass",
                            "Output": {
                                "sku": "{% $states.input.sku %}",
                                "idx": "{% $states.input.idx %}",
                                "total": "{% $states.input.qty * $states.input.rate %}",
                            },
                            "End": True,
                        },
                    },
                },
                "Output": {
                    "lines": "{% $states.result %}",
                    "grand": "{% $sum($states.result.total) %}",
                    "count": "{% $count($states.result) %}",
                },
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    orders = [{"sku": "a", "qty": 2}, {"sku": "b", "qty": 0}, {"sku": "c", "qty": 5},
              {"sku": "d", "qty": 1}]
    exe = _run_to_terminal(ctx, sm_arn, {"orders": orders, "rate": 3}, timeout_s=60)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    expected = {
        "lines": [{"sku": "a", "idx": 0, "total": 6}, {"sku": "c", "idx": 1, "total": 15},
                  {"sku": "d", "idx": 2, "total": 3}],
        "grand": 24,
        "count": 3,
    }
    assert out == expected, (
        f"Map output {out!r}, expected {expected!r}: sku 'b' (qty 0) must be filtered out by the "
        f"Items expression, and Map.Item.Index counts positions in the FILTERED array"
    )

    events = _history(ctx, exe["executionArn"])
    started = [e for e in events if e["type"] == "MapIterationStarted"]
    assert len(started) == 3, (
        f"{len(started)!r} MapIterationStarted events; the Items expression yields 3 items"
    )
    map_started = [e["mapStateStartedEventDetails"]["length"] for e in events
                   if e["type"] == "MapStateStarted"]
    assert map_started == [3], f"MapStateStarted length {map_started!r}, expected [3]"


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_role(ctx):
    """A bare execution role: an INLINE Map of Pass states calls no service."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    arn = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s, max_attempts=4):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
