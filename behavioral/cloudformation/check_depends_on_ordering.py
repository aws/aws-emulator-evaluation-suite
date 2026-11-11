"""depends-on-ordering."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "depends-on-ordering"
GROUP = 'resources'
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

def _depends_on_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "First": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Second": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                       "DependsOn": "First"},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DependsOn does not prevent creation (just orders it): the stack
    completes, and an independent read of the stack's own event history shows
    First actually reached CREATE_COMPLETE no later than Second."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _depends_on_template())
    status = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    events = cf.describe_stack_events(StackName=name)["StackEvents"]
    complete_time = {}
    for e in events:
        if e["LogicalResourceId"] in {"First", "Second"} and e["ResourceStatus"] == "CREATE_COMPLETE":
            complete_time[e["LogicalResourceId"]] = e["Timestamp"]
    assert set(complete_time) == {"First", "Second"}, (
        f"expected CREATE_COMPLETE events for both First and Second, got {complete_time}"
    )
    assert complete_time["First"] <= complete_time["Second"], (
        "First must complete no later than Second given DependsOn=First",
        complete_time,
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
