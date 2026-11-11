"""stack-outputs-present."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-outputs-present"
GROUP = 'stack_outputs'
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

def _outputs_template(output_value="hello-sim2real"):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {
            "HandleUrl": {"Description": "The presigned URL", "Value": {"Ref": "Handle"}},
            "StaticOutput": {"Description": "A static output value", "Value": output_value},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Stack Outputs section values are retrievable via DescribeStacks."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(ctx, cf, _outputs_template("test-value-123"))
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    }
    assert "StaticOutput" in outputs, f"expected 'StaticOutput' in Outputs, got keys={sorted(outputs)}"
    assert outputs["StaticOutput"] == "test-value-123", (
        f"expected StaticOutput=='test-value-123', got {outputs['StaticOutput']!r}"
    )
    assert "HandleUrl" in outputs, f"expected 'HandleUrl' in Outputs, got keys={sorted(outputs)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
