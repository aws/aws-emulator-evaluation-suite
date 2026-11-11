"""fn-find-in-map-nested-lookup-drives-property."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fn-find-in-map-nested-lookup-drives-property"
GROUP = 'intrinsic_functions'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


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
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised. Raise if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


_TIERS = {"dev": {"Tier": "bronze", "Retention": "1"},
          "prod": {"Tier": "gold", "Retention": "30"}}


def _template(param_name, mappings):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Env": {"Type": "String", "AllowedValues": ["dev", "prod"]}},
        "Mappings": {"EnvTiers": mappings},
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": param_name,
                    "Type": "String",
                    # FindInMap with a Ref'd top-level key, joined with a second
                    # FindInMap on the same map -- resolution must be per-key.
                    "Value": {"Fn::Join": ["-", [
                        {"Fn::FindInMap": ["EnvTiers", {"Ref": "Env"}, "Tier"]},
                        {"Fn::FindInMap": ["EnvTiers", {"Ref": "Env"}, "Retention"]},
                    ]]},
                },
            },
        },
        "Outputs": {
            # FindInMap nested inside Fn::Sub's variable map.
            "Described": {"Value": {"Fn::Sub": [
                "tier=${T} keep=${R}",
                {"T": {"Fn::FindInMap": ["EnvTiers", {"Ref": "Env"}, "Tier"]},
                 "R": {"Fn::FindInMap": ["EnvTiers", {"Ref": "Env"}, "Retention"]}},
            ]}},
            # A literal (non-Ref) top-level key on the same map.
            "DevTier": {"Value": {"Fn::FindInMap": ["EnvTiers", "dev", "Tier"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::FindInMap resolves Ref'd and literal two-level lookups nested in Fn::Join and Fn::Sub, and
    the value reaches the provisioned resource; a top-level key absent from the map is rejected with
    ValidationError instead of resolving to an empty string."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-behav-findinmap-")
    param_name = "/" + ctx.unique_name("sim2real-behav-findinmap-p-")

    cf.create_stack(
        StackName=stack,
        TemplateBody=_template(param_name, _TIERS),
        Parameters=[{"ParameterKey": "Env", "ParameterValue": "prod"}],
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )

    provisioned = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert provisioned == "gold-30", (
        f"FindInMap(EnvTiers, prod, *) must resolve to gold/30 in the provisioned "
        f"resource, got {provisioned!r}"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in created.get("Outputs", [])}
    assert outputs.get("Described") == "tier=gold keep=30", (
        f"FindInMap nested in Fn::Sub must resolve, got {outputs.get('Described')!r}"
    )
    assert outputs.get("DevTier") == "bronze", (
        f"a literal top-level FindInMap key must resolve independently of the Ref'd "
        f"one, got {outputs.get('DevTier')!r}"
    )

    # Drop the 'prod' entry so the Ref'd key has no match.
    bad_stack = ctx.unique_name("sim2real-behav-findinmap-bad-")
    code, message = _error(lambda: cf.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(param_name + "-bad", {"dev": _TIERS["dev"]}),
        Parameters=[{"ParameterKey": "Env", "ParameterValue": "prod"}],
    ))
    assert code == "ValidationError", (
        f"an unresolvable FindInMap key must be rejected with ValidationError, got {code!r}"
    )
    expected_message = "Template error: Unable to get mapping for EnvTiers::prod::Tier"
    assert message == expected_message, (
        f"the rejection must name the failing mapping lookup: expected {expected_message!r}, "
        f"got {message!r}"
    )
    assert _describe(cf, bad_stack) is None, (
        f"a template rejected for an unresolvable FindInMap must not create a stack: {bad_stack}"
    )

    ok_stack = ctx.unique_name("sim2real-behav-findinmap-ok-")
    ok_param = "/" + ctx.unique_name("sim2real-behav-findinmap-okp-")
    cf.create_stack(
        StackName=ok_stack,
        TemplateBody=_template(ok_param, {"dev": _TIERS["dev"]}),
        Parameters=[{"ParameterKey": "Env", "ParameterValue": "dev"}],
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=ok_stack))
    ok = _wait_terminal(cf, ok_stack)
    assert ok["StackStatus"] == "CREATE_COMPLETE", (
        f"control stack must still create, got {ok['StackStatus']!r}: "
        f"{ok.get('StackStatusReason')!r}"
    )
    ok_value = ssm.get_parameter(Name=ok_param)["Parameter"]["Value"]
    assert ok_value == "bronze-1", (
        f"control FindInMap(EnvTiers, dev, *) must resolve to bronze/1 in the "
        f"provisioned resource, got {ok_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
