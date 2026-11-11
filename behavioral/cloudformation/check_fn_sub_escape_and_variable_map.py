"""fn-sub-escape-and-variable-map."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fn-sub-escape-and-variable-map"
GROUP = 'intrinsic_functions'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it does not exist."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _template(param_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Who": {"Type": "String"}},
        "Resources": {
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": param_name, "Type": "String", "Value": {"Fn::Sub": "${!Literal}-${AWS::Region}"}},
            },
        },
        "Outputs": {
            "Escaped": {"Value": {"Fn::Sub": "${!Literal}-${AWS::Region}"}},
            "Mapped": {"Value": {"Fn::Sub": ["${Greeting}, ${Who}", {"Greeting": "hello"}]}},
            "Shadowed": {"Value": {"Fn::Sub": ["${Handle}", {"Handle": "from-the-map"}]}},
        },
    })

@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::Sub resolves its three documented forms: ${!Literal} becomes the literal "${Literal}" (both
    in an output and in a provisioned resource), the variable map supplies values beside template
    parameters, and a map key named like a resource wins over that resource's Ref."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-behav-subescape-")
    param = "/" + ctx.unique_name("sim2real-behav-subescape-p-")

    cf.create_stack(StackName=stack, TemplateBody=_template(param),
                    Parameters=[{"ParameterKey": "Who", "ParameterValue": "world"}])
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    outputs = _outputs(created)
    expected_escape = "${Literal}-" + ctx.region
    assert outputs.get("Escaped") == expected_escape, f"${{!Literal}} must emit a literal; outputs {outputs!r}"
    assert outputs.get("Mapped") == "hello, world", f"the variable map must supply Greeting; outputs {outputs!r}"
    assert outputs.get("Shadowed") == "from-the-map", f"a map key must win over a resource Ref; outputs {outputs!r}"
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value == expected_escape, f"the provisioned value must carry the literal; got {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
