"""describe-stack-events-present."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-stack-events-present"
GROUP = 'stack_events'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DescribeStackEvents returns events for the stack just created: every event carries its
    StackId, EventIds are unique, and the stack-level events include CREATE_COMPLETE and name
    the StackId as PhysicalResourceId."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(
        ctx, cf, _handle_template(), tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]

    resp = cf.describe_stack_events(StackName=name)
    events = resp.get("StackEvents", [])
    assert len(events) > 0, f"Expected at least one stack event for {name}, got none"

    event_ids = [e.get("EventId") for e in events]
    assert len(event_ids) == len(set(event_ids)), (
        f"expected unique EventIds, got duplicates in {event_ids}"
    )

    other_stack_ids = {e.get("StackId") for e in events} - {stack_id}
    assert not other_stack_ids, (
        f"every event for {name} must carry its own StackId {stack_id!r}, "
        f"found events referencing other stacks: {other_stack_ids}"
    )

    stack_level = [e for e in events if e.get("ResourceType") == "AWS::CloudFormation::Stack"]
    assert stack_level, f"no stack-level event among {events}"
    assert any(e.get("ResourceStatus") == "CREATE_COMPLETE" for e in stack_level), (
        f"expected a stack-level CREATE_COMPLETE event, "
        f"got statuses {[e.get('ResourceStatus') for e in stack_level]}"
    )
    assert all(e.get("PhysicalResourceId") == stack_id for e in stack_level), (
        f"stack-level event PhysicalResourceId must equal the stack's own "
        f"StackId {stack_id!r}, got {[e.get('PhysicalResourceId') for e in stack_level]}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
