"""fn-sub."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fn-sub"
GROUP = 'intrinsic_functions'
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

def _intrinsics_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Env": {"Type": "String", "Default": "dev"},
            "Items": {"Type": "CommaDelimitedList", "Default": "alpha,beta,gamma"},
        },
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {
            "Joined": {"Value": {"Fn::Join": ["-", ["sim2real", {"Ref": "Env"}]]}},
            "Selected": {"Value": {"Fn::Select": ["1", {"Ref": "Items"}]}},
            "Subbed": {"Value": {"Fn::Sub": "stack-${AWS::StackName}-region-${AWS::Region}"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Fn::Sub substitutes pseudo-parameters (AWS::StackName, AWS::Region)."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(
        ctx, cf, _intrinsics_template(),
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    }
    subbed = outputs["Subbed"]
    assert f"stack-{name}" in subbed, (
        f"expected AWS::StackName substituted into Subbed, got {subbed!r}"
    )
    assert f"region-{ctx.region}" in subbed, (
        f"expected AWS::Region ({ctx.region!r}) substituted into Subbed, got {subbed!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
