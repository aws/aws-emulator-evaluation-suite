"""parameter-no-echo."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-no-echo"
GROUP = 'stack_parameters'
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

def _parameters_template(*, default=None, allowed_values=None, no_echo=False, control_default=None):
    param = {"Type": "String", "Description": "Queue suffix"}
    if default is not None:
        param["Default"] = default
    if allowed_values:
        param["AllowedValues"] = allowed_values
    if no_echo:
        param["NoEcho"] = True
    parameters = {"Suffix": param}
    outputs = {"ParamValue": {"Value": {"Ref": "Suffix"}}}
    if control_default is not None:
        parameters["PlainSuffix"] = {
            "Type": "String",
            "Description": "Non-NoEcho control parameter",
            "Default": control_default,
        }
        outputs["ControlValue"] = {"Value": {"Ref": "PlainSuffix"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": parameters,
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """NoEcho parameters are masked in DescribeStacks; a sibling non-NoEcho
    parameter in the same stack is a control proving the masking is
    NoEcho-specific, not a blanket redaction of every parameter."""
    cf = ctx.client("cloudformation")
    name = _create_and_wait(
        ctx, cf,
        _parameters_template(default="secret-val", no_echo=True, control_default="visible-val"),
        tags=[{"Key": "sim2real-check", "Value": "parameter-no-echo"}],
    )
    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    params = {p["ParameterKey"]: p["ParameterValue"] for p in stack.get("Parameters", [])}
    assert "Suffix" in params, "Parameter 'Suffix' not found in stack parameters"
    assert params["Suffix"] == "****", (
        f"NoEcho param should be masked, got: {params['Suffix']!r}"
    )
    assert "PlainSuffix" in params, "control parameter 'PlainSuffix' not found in stack parameters"
    assert params["PlainSuffix"] == "visible-val", (
        f"non-NoEcho control param should not be masked, got: {params['PlainSuffix']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
