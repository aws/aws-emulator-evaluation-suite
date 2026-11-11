"""list-stack-resources."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-stack-resources"
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

def _two_handles_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle1": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Handle2": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStackResources returns exactly the stack's resources, each fully and
    correctly described (type, terminal status, a distinct physical id) — not just
    their logical ids echoed back from the template."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _two_handles_template())
    resp = cf.list_stack_resources(StackName=name)
    by_logical = {r["LogicalResourceId"]: r for r in resp["StackResourceSummaries"]}
    assert set(by_logical) == {"Handle1", "Handle2"}, (
        f"expected exactly {{Handle1, Handle2}}, got {sorted(by_logical)}"
    )
    for logical_id in ("Handle1", "Handle2"):
        resource = by_logical[logical_id]
        assert resource["ResourceStatus"] == "CREATE_COMPLETE", (
            f"{logical_id} status {resource['ResourceStatus']!r}, expected CREATE_COMPLETE"
        )
        assert resource["ResourceType"] == "AWS::CloudFormation::WaitConditionHandle", (
            f"{logical_id} type {resource['ResourceType']!r}, "
            "expected AWS::CloudFormation::WaitConditionHandle"
        )
        assert resource.get("PhysicalResourceId"), f"{logical_id} has no PhysicalResourceId"
    assert by_logical["Handle1"]["PhysicalResourceId"] != by_logical["Handle2"]["PhysicalResourceId"], (
        "Handle1 and Handle2 resolved to the same PhysicalResourceId "
        f"({by_logical['Handle1']['PhysicalResourceId']!r})"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
