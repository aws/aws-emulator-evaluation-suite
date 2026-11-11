"""foreach-outside-allowed-sections-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "foreach-outside-allowed-sections-rejected"
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
    """(code, message) of the ClientError ``fn`` raises; raises when the call succeeds."""
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


_TRANSFORM = "AWS::LanguageExtensions"


def _base():
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": _TRANSFORM,
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }


def _with_parameters_loop():
    t = _base()
    t["Parameters"] = {"Fn::ForEach::Params": ["Name", ["Alpha", "Beta"], {"${Name}": {"Type": "String", "Default": "x"}}]}
    return json.dumps(t)


def _with_mappings_loop():
    t = _base()
    t["Mappings"] = {"Fn::ForEach::Maps": ["Name", ["Alpha", "Beta"], {"${Name}": {"Key": {"Value": "x"}}}]}
    return json.dumps(t)


def _with_outputs_loop():
    t = _base()
    t["Outputs"] = {"Fn::ForEach::Outs": ["Name", ["Alpha", "Beta"], {"${Name}Out": {"Value": {"Fn::Sub": "${Name}-value"}}}]}
    return json.dumps(t)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Fn::ForEach in Parameters is refused with no stack; in Mappings the stack rolls back with nothing
    provisioned; the same loop in Outputs expands into one output per collection item."""
    cf = ctx.client("cloudformation")

    in_params = ctx.unique_name("sim2real-behav-foreach-par-")
    ctx.on_cleanup(lambda: _delete_if_present(cf, in_params))
    code, msg = _error(lambda: cf.create_stack(StackName=in_params, TemplateBody=_with_parameters_loop(),
                                               Capabilities=["CAPABILITY_AUTO_EXPAND"]))
    assert code == "ValidationError", f"ForEach in Parameters gave {code!r}: {msg!r}"
    # Parameters are validated before the transform runs, so the loop key fails as a parameter name.
    assert msg == "Template format error: Parameter name Fn::ForEach::Params is non alphanumeric.", (
        f"ForEach in Parameters must be refused as a parameter name; got {msg!r}"
    )
    assert _describe(cf, in_params) is None, f"a rejected template left a stack behind: {in_params}"

    in_maps = ctx.unique_name("sim2real-behav-foreach-map-")
    ctx.on_cleanup(lambda: _delete_if_present(cf, in_maps))
    # The create is accepted; the transform fails afterwards and the stack rolls back.
    stack_id = cf.create_stack(StackName=in_maps, TemplateBody=_with_mappings_loop(),
                               Capabilities=["CAPABILITY_AUTO_EXPAND"])["StackId"]
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack_id))
    final = _wait_terminal(cf, stack_id)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"ForEach in Mappings must roll back; got {final['StackStatus']!r}: {final.get('StackStatusReason')!r}"
    )
    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    assert resources == [], f"a failed transform must provision nothing; got {resources!r}"
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    reasons = [e.get("ResourceStatusReason") for page in pages for e in page["StackEvents"]]
    expected = "Transform AWS::LanguageExtensions failed with: Error parsing the template. Rollback requested by user."
    assert expected in reasons, f"expected the rollback reason {expected!r}; events gave {reasons!r}"

    ok = ctx.unique_name("sim2real-behav-foreach-out-")
    cf.create_stack(StackName=ok, TemplateBody=_with_outputs_loop(), Capabilities=["CAPABILITY_AUTO_EXPAND"])
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=ok))
    created = _wait_terminal(cf, ok)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"ForEach in Outputs must create; got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    assert _outputs(created) == {"AlphaOut": "Alpha-value", "BetaOut": "Beta-value"}, (
        f"ForEach in Outputs must expand one output per item; got {_outputs(created)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
