"""stack-events-ordering."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-events-ordering"
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

def _create_and_wait(ctx, cf, template, *, tags):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=template, Tags=tags)["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
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
    """A create emits exactly the five stack and resource events, returned newest first."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(
        ctx, cf, _handle_template(),
        tags=[{"Key": "sim2real", "Value": "stack-events-ordering"}],
    )
    resp = cf.describe_stack_events(StackName=name)
    events = resp.get("StackEvents", [])
    sequence = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason")) for e in events
    ]
    expected = [
        (name, "CREATE_COMPLETE", None),
        ("Handle", "CREATE_COMPLETE", None),
        ("Handle", "CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("Handle", "CREATE_IN_PROGRESS", None),
        (name, "CREATE_IN_PROGRESS", "User Initiated"),
    ]
    assert sequence == expected, f"stack events newest first: expected {expected!r}, got {sequence!r}"
    timestamps = [e["Timestamp"] for e in events]
    for i in range(len(timestamps) - 1):
        assert timestamps[i] >= timestamps[i + 1], (
            f"Events not in reverse chronological order at index {i}: "
            f"{timestamps[i]!r} < {timestamps[i + 1]!r}"
        )


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
