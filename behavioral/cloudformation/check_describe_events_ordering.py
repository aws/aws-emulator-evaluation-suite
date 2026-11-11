"""describe-events-ordering."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-events-ordering"
GROUP = "ordering"
SERVICES = ["cloudformation"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DescribeEvents returns operation events for a stack newest-first, and CREATE_STACK
    events all precede UPDATE_STACK events in real time regardless of list position."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eventsorder-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(30)),
        Tags=[{"Key": "sim2real-check", "Value": "describe-events-ordering"}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    create_status = _wait_stack_terminal(cfn, stack_id)
    assert create_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {create_status}"

    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(_template(90)))
    update_status = _wait_stack_terminal(cfn, stack_id)
    assert update_status == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {update_status}"

    events = _list_all_events(cfn, stack_id)
    assert len(events) >= 4, f"expected multiple operation events, got {len(events)}"

    # DescribeEvents groups by operation and orders newest-first.
    timestamps = [e["Timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True), (
        f"DescribeEvents must return OperationEvents newest-first, got timestamps {timestamps}"
    )

    create_ts = [e["Timestamp"] for e in events if e.get("OperationType") == "CREATE_STACK"]
    update_ts = [e["Timestamp"] for e in events if e.get("OperationType") == "UPDATE_STACK"]
    assert create_ts, "no CREATE_STACK events found"
    assert update_ts, "no UPDATE_STACK events found"

    # create really did happen before update in real time, independent of the list's sort order
    assert max(create_ts) <= min(update_ts), (
        "CREATE_STACK events must all precede UPDATE_STACK events in time "
        f"(max create={max(create_ts)}, min update={min(update_ts)})"
    )


def _template(timeout: int) -> dict:
    return {"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": timeout}}}}


def _list_all_events(cfn, stack_id: str) -> list:
    events: list = []
    kwargs = {"StackName": stack_id}
    while True:
        resp = cfn.describe_events(**kwargs)
        events.extend(resp.get("OperationEvents", []))
        token = resp.get("NextToken")
        if not token:
            return events
        kwargs["NextToken"] = token


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
