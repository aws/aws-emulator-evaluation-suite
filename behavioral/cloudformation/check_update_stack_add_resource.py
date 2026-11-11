"""update-stack-add-resource."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stack-add-resource"
GROUP = 'stack_update'
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

def _two_handles_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle1": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Handle2": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """UpdateStack adding a second resource reaches UPDATE_COMPLETE and the new
    resource is independently observable, provisioned, with its own physical id."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _handle_template())
    cf.update_stack(StackName=name, TemplateBody=_two_handles_template())
    status = _wait_terminal(cf, name)
    assert status == "UPDATE_COMPLETE", f"Expected UPDATE_COMPLETE, got {status}"

    resources = {
        r["LogicalResourceId"]: r
        for r in cf.describe_stack_resources(StackName=name)["StackResources"]
    }
    assert set(resources) == {"Handle1", "Handle2"}, (
        f"Expected Handle1 and Handle2 present, got {sorted(resources)}"
    )
    added = resources["Handle2"]
    assert added["ResourceStatus"] == "CREATE_COMPLETE", (
        f"Expected Handle2 ResourceStatus CREATE_COMPLETE, got {added['ResourceStatus']!r}"
    )
    physical_id = added.get("PhysicalResourceId")
    assert physical_id, "Expected Handle2 to have a non-empty PhysicalResourceId"
    assert physical_id.startswith("https://"), (
        f"Expected Handle2 PhysicalResourceId to be a presigned URL, got {physical_id!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
