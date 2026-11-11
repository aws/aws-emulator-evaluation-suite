"""fn-if-condition-true."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fn-if-condition-true"
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

def _conditions_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "CreateExtra": {"Type": "String", "Default": "true",
                            "AllowedValues": ["true", "false"]}
        },
        "Conditions": {"ShouldCreate": {"Fn::Equals": [{"Ref": "CreateExtra"}, "true"]}},
        "Resources": {
            "Handle1": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Handle2": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                        "Condition": "ShouldCreate"},
        },
        "Outputs": {"Created": {"Value": {"Fn::If": ["ShouldCreate", "yes", "no"]}}},
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Fn::If evaluates the true branch when condition is true."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(
        ctx, cf, _conditions_template(),
        parameters=[{"ParameterKey": "CreateExtra", "ParameterValue": "true"}],
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    }
    assert outputs["Created"] == "yes", (
        f"Fn::If(ShouldCreate, 'yes', 'no') with ShouldCreate true must resolve to "
        f"'yes', got {outputs.get('Created')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
