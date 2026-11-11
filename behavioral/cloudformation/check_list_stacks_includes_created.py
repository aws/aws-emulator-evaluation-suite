"""list-stacks-includes-created."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-stacks-includes-created"
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
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return (name, stack_id)."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    stack_id = cf.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name, stack_id

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStacks includes our newly created stack, reporting the same StackId and status
    CreateStack itself confirmed -- not just a name match."""
    cf = ctx.client("cloudformation")
    name, stack_id = _create_and_wait(
        ctx, cf, _handle_template(), tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    paginator = cf.get_paginator("list_stacks")
    match = None
    for page in paginator.paginate(StackStatusFilter=["CREATE_COMPLETE"]):
        for summary in page.get("StackSummaries", []):
            if summary["StackName"] == name:
                match = summary
                break
        if match:
            break
    assert match is not None, f"Stack {name} not found in ListStacks(CREATE_COMPLETE)"
    assert match["StackId"] == stack_id, (
        f"ListStacks StackId {match['StackId']!r} for {name} != CreateStack StackId {stack_id!r}"
    )
    assert match["StackStatus"] == "CREATE_COMPLETE", (
        f"ListStacks reported StackStatus {match['StackStatus']!r} for {name}, expected CREATE_COMPLETE"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
