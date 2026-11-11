"""find-in-map-default-value-without-transform."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "find-in-map-default-value-without-transform"
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
    lookup = lambda top, second: {"Fn::FindInMap": ["Tiers", top, second, {"DefaultValue": "fallback"}]}  # noqa: E731
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Env": {"Type": "String"}},
        "Mappings": {"Tiers": {"dev": {"Name": "bronze"}, "prod": {"Name": "gold"}}},
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": param_name, "Type": "String", "Value": lookup({"Ref": "Env"}, "Name")},
            },
        },
        "Outputs": {
            "Present": {"Value": lookup("dev", "Name")},
            "MissingTop": {"Value": lookup({"Ref": "Env"}, "Name")},
            "MissingSecond": {"Value": lookup("prod", "Retention")},
        },
    })

@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FindInMap's DefaultValue works without the LanguageExtensions transform: a missing top-level
    or second-level key resolves to the default, a present key to the map's value, and the default
    reaches the provisioned resource, not only the outputs."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-behav-fimdefault-")
    param = "/" + ctx.unique_name("sim2real-behav-fimdefault-p-")

    cf.create_stack(StackName=stack, TemplateBody=_template(param),
                    Parameters=[{"ParameterKey": "Env", "ParameterValue": "staging"}])
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"DefaultValue without the transform must create; got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    outputs = _outputs(created)
    assert outputs.get("Present") == "bronze", f"a present key must resolve to the map value; outputs {outputs!r}"
    assert outputs.get("MissingTop") == "fallback", f"a missing top-level key must take the default; outputs {outputs!r}"
    assert outputs.get("MissingSecond") == "fallback", f"a missing second-level key must take the default; outputs {outputs!r}"
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value == "fallback", f"the provisioned parameter must carry the default; got {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
