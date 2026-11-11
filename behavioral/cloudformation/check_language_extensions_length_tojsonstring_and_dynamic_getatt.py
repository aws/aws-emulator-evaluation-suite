"""language-extensions-length-tojsonstring-and-dynamic-getatt."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "language-extensions-length-tojsonstring-and-dynamic-getatt"
GROUP = 'language_extensions'
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
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_if_present(cf, name):
    """Delete a stack that a refused create should never have made; a no-op when it does not exist."""
    if _describe(cf, name) is not None:
        cf.delete_stack(StackName=name)


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

_OUTPUTS = {
    "Count": {"Value": {"Fn::Length": {"Ref": "Items"}}},
    "Json": {"Value": {"Fn::ToJsonString": {"key": "value", "list": ["x", "y"]}}},
    "Dynamic": {"Value": {"Fn::GetAtt": ["Param", {"Ref": "Attr"}]}},
}


def _template(param_name, *, transform, outputs=("Count", "Json", "Dynamic")):
    t = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Items": {"Type": "CommaDelimitedList", "Default": "a,b,c"},
            "Attr": {"Type": "String", "Default": "Value"},
        },
        "Resources": {
            "Param": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": param_name, "Type": "String", "Value": "payload"}},
        },
        "Outputs": {key: _OUTPUTS[key] for key in outputs},
    }
    if transform:
        t["Transform"] = "AWS::LanguageExtensions"
    return json.dumps(t)


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With the LanguageExtensions transform, Fn::Length counts a list parameter and Fn::ToJsonString
    serialises an object; without it Fn::Length is refused synchronously and no stack survives, while
    Fn::GetAtt with a Ref'd attribute name resolves natively.
    """
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-behav-langext-")
    param = "/" + ctx.unique_name("sim2real-behav-langext-p-")

    cf.create_stack(StackName=stack, TemplateBody=_template(param, transform=True), Capabilities=["CAPABILITY_AUTO_EXPAND"])
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    outputs = _outputs(created)
    assert outputs.get("Count") == "3", f"Fn::Length of a three-item list must be 3; outputs {outputs!r}"
    assert outputs.get("Json") == '{"key":"value","list":["x","y"]}', f"Fn::ToJsonString output was {outputs.get('Json')!r}"
    assert outputs.get("Dynamic") == "payload", f"GetAtt with a Ref'd attribute name must resolve; outputs {outputs!r}"

    # Without the transform Fn::Length is an unknown function, refused before any stack exists.
    plain = ctx.unique_name("sim2real-behav-langext-plain-")
    ctx.on_cleanup(lambda: _delete_if_present(cf, plain))
    code, msg = _error(lambda: cf.create_stack(
        StackName=plain, TemplateBody=_template(param + "-plain", transform=False, outputs=("Count",))))
    assert code == "ValidationError", f"Fn::Length without the transform gave {code!r}: {msg!r}"
    supported = ", ".join([
        "Fn::GetStackOutput", "Fn::AccountIdFromAlias", "Fn::GetConstantAZs", "Fn::Base64", "Fn::GetAtt",
        "Fn::GetAZs", "Fn::ImportValue", "Fn::Join", "Fn::Split", "Fn::FindInMap", "Fn::Select", "Ref",
        "Fn::Equals", "Fn::If", "Fn::Not", "Condition", "Fn::And", "Fn::Or", "Fn::Contains",
        "Fn::EachMemberEquals", "Fn::EachMemberIn", "Fn::ValueOf", "Fn::ValueOfAll", "Fn::RefAll",
        "Fn::Sub", "Fn::Cidr",
    ])
    expected = f"Template Error: Encountered unsupported function: Fn::Length Supported functions are: [{supported}]"
    assert msg == expected, f"the rejection message was {msg!r}"
    assert _describe(cf, plain) is None, f"a rejected template left a stack behind: {plain}"

    # A Ref'd GetAtt attribute name needs no transform.
    native = ctx.unique_name("sim2real-behav-langext-native-")
    cf.create_stack(StackName=native, TemplateBody=_template(param + "-native", transform=False, outputs=("Dynamic",)))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=native))
    created = _wait_terminal(cf, native)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"a Ref'd GetAtt attribute without the transform must create; got {created['StackStatus']!r}"
    )
    assert _outputs(created) == {"Dynamic": "payload"}, f"native dynamic GetAtt outputs were {_outputs(created)!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
