"""rules-assertions-gate-stack-creation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rules-assertions-gate-stack-creation-rejected"
GROUP = 'template_rules'
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



def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


_PROD_RULE = "prod stacks must use the large size"
_TIERS_RULE = "every tier must be gold or silver"


def _template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Env": {"Type": "String", "AllowedValues": ["dev", "prod"]},
            "Size": {"Type": "String", "AllowedValues": ["small", "large"]},
            "Tiers": {"Type": "CommaDelimitedList"},
        },
        "Rules": {
            "ProdRequiresLarge": {
                "RuleCondition": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "Assertions": [{"Assert": {"Fn::Equals": [{"Ref": "Size"}, "large"]}, "AssertDescription": _PROD_RULE}],
            },
            "TiersAllowed": {
                "Assertions": [{
                    "Assert": {"Fn::EachMemberIn": [{"Ref": "Tiers"}, ["gold", "silver"]]},
                    "AssertDescription": _TIERS_RULE,
                }],
            },
        },
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Env": {"Value": {"Ref": "Env"}}},
    })


def _params(env, size, tiers):
    return [
        {"ParameterKey": "Env", "ParameterValue": env},
        {"ParameterKey": "Size", "ParameterValue": size},
        {"ParameterKey": "Tiers", "ParameterValue": tiers},
    ]

def _assert_rolled_back(ctx, cf, name, body, params, description):
    """Create a stack whose rule assertion fails; assert it rolls back with no resource and the exact reason."""
    stack_id = cf.create_stack(StackName=name, TemplateBody=body, Parameters=params)["StackId"]
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack_id))
    final = _wait_terminal(cf, stack_id)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a failing rule assertion must roll the create back; got {final['StackStatus']!r}: "
        f"{final.get('StackStatusReason')!r}"
    )
    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    assert resources == [], f"a failing rule assertion must provision nothing; got {resources!r}"
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    reasons = [e.get("ResourceStatusReason") for page in pages for e in page["StackEvents"]]
    expected = f"Parameter validation failed: assertion error: {description}. Rollback requested by user."
    assert expected in reasons, f"no stack event carries {expected!r}; reasons were {reasons!r}"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A false RuleCondition skips its assertions; a failing assertion (plain or Fn::EachMemberIn)
    rolls the create back with nothing provisioned and its AssertDescription in the stack events;
    the same template creates once every applicable assertion holds.
    """
    cf = ctx.client("cloudformation")
    body = _template()

    # Assertion of a rule whose RuleCondition is false is skipped: dev + small creates.
    dev = ctx.unique_name("sim2real-behav-rules-dev-")
    cf.create_stack(StackName=dev, TemplateBody=body, Parameters=_params("dev", "small", "gold"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=dev))
    created = _wait_terminal(cf, dev)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"a false RuleCondition must skip its assertion; got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )

    # The same rule with its condition true and its assertion false is accepted, then rolls back
    # before any resource is provisioned, naming the AssertDescription.
    _assert_rolled_back(ctx, cf, ctx.unique_name("sim2real-behav-rules-ps-"), body,
                        _params("prod", "small", "gold"), _PROD_RULE)
    # Fn::EachMemberIn fails when one member is outside the allowed set.
    _assert_rolled_back(ctx, cf, ctx.unique_name("sim2real-behav-rules-tier-"), body,
                        _params("dev", "small", "gold,copper"), _TIERS_RULE)

    # Control: prod with large and allowed tiers satisfies every assertion and creates.
    prod_large = ctx.unique_name("sim2real-behav-rules-pl-")
    cf.create_stack(StackName=prod_large, TemplateBody=body, Parameters=_params("prod", "large", "gold,silver"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=prod_large))
    ok = _wait_terminal(cf, prod_large)
    assert ok["StackStatus"] == "CREATE_COMPLETE", (
        f"the passing control must create; got {ok['StackStatus']!r}: {ok.get('StackStatusReason')!r}"
    )
    assert _outputs(ok).get("Env") == "prod", f"control stack outputs were {_outputs(ok)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
