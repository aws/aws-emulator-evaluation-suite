"""delete-stack-reaches-complete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-stack-reaches-complete"
GROUP = 'stack_lifecycle'
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
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _wait_deleted(cf, stack_id, timeout_s=180):
    """Poll DescribeStacks by StackId until DELETE_COMPLETE or DELETE_FAILED; return that status."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(2)

def _create_and_wait(ctx, cf, template, *, tags):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return name and StackId."""
    name = ctx.unique_name("sim2real-behav-stk-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=template, Tags=tags)["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name, stack_id

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeleteStack transitions to DELETE_COMPLETE."""
    cf = ctx.client("cloudformation")
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]
    name, stack_id = _create_and_wait(ctx, cf, _handle_template(), tags=stack_tags)
    cf.delete_stack(StackName=name)
    outcome = _wait_deleted(cf, stack_id)
    assert outcome == "DELETE_COMPLETE", (
        f"stack {name} delete outcome via an independent DescribeStacks read by StackId was "
        f"{outcome!r}, expected DELETE_COMPLETE"
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
