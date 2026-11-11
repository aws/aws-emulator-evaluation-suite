"""unresolvable-output-intrinsic-fails-the-stack-rather-than-vanishing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unresolvable-output-intrinsic-fails-the-stack-rather-than-vanishing"
GROUP = "template_validation"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 240.0
JOIN_PARTS = ["alpha", "beta"]
BOGUS_FUNCTION = "Fn::NoSuchIntrinsic"
MISSING_MAP_KEY = "nosuchkey"
# CloudFormation's refusal of an unknown intrinsic enumerates the functions it does support.
_SUPPORTED_FUNCTIONS = (
    "Fn::GetStackOutput, Fn::AccountIdFromAlias, Fn::GetConstantAZs, Fn::Base64, Fn::GetAtt, "
    "Fn::GetAZs, Fn::ImportValue, Fn::Join, Fn::Split, Fn::FindInMap, Fn::Select, Ref, Fn::Equals, "
    "Fn::If, Fn::Not, Condition, Fn::And, Fn::Or, Fn::Contains, Fn::EachMemberEquals, "
    "Fn::EachMemberIn, Fn::ValueOf, Fn::ValueOfAll, Fn::RefAll, Fn::Sub, Fn::Cidr"
)
BOGUS_FUNCTION_MESSAGE = (
    f"Template Error: Encountered unsupported function: {BOGUS_FUNCTION} "
    f"Supported functions are: [{_SUPPORTED_FUNCTIONS}]"
)
MISSING_MAP_KEY_MESSAGE = f"Template error: Unable to get mapping for EnvMap::{MISSING_MAP_KEY}::size"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unresolvable Outputs entry fails CreateStack and ValidateTemplate with ValidationError
    and leaves no stack; it is never silently omitted from a successful stack's Outputs.
    """
    cf = ctx.client("cloudformation")

    # --- Beat 1: positive control -- the same template shape, fully resolvable -------------------
    # Asserts COMPLETENESS, not membership: this is the read that would catch a target which drops
    # an output it cannot resolve, and it must be clean before the negatives mean anything.
    good_stack = ctx.unique_name("sim2real-cfn-outres-good-")
    cf.create_stack(StackName=good_stack, TemplateBody=_resolvable_template())
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=good_stack))
    good = _poll_stack(cf, good_stack)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"positive control {good_stack!r} must reach CREATE_COMPLETE, got {good['StackStatus']!r} "
        f"({good.get('StackStatusReason')!r})"
    )
    good_outputs = {o["OutputKey"]: o["OutputValue"] for o in good.get("Outputs") or []}
    assert set(good_outputs) == {"Mapped", "Joined"}, (
        f"the control declares exactly two Outputs and both must come back; got "
        f"{sorted(good_outputs)!r}"
    )
    assert good_outputs["Joined"] == "-".join(JOIN_PARTS), (
        f"the control's Fn::Join must resolve to {'-'.join(JOIN_PARTS)!r}, got {good_outputs['Joined']!r}"
    )
    assert good_outputs["Mapped"] == "large", (
        f"the control's FindInMap must resolve to 'large', got {good_outputs['Mapped']!r}"
    )

    # --- Beat 2: an unknown intrinsic in Outputs is refused --------------------------------------
    bogus_fn_body = _template_with_output({BOGUS_FUNCTION: [JOIN_PARTS[0], JOIN_PARTS[1]]})
    bogus_fn_stack = ctx.unique_name("sim2real-cfn-outres-fn-")
    fn_error = _client_error(
        lambda: cf.create_stack(StackName=bogus_fn_stack, TemplateBody=bogus_fn_body)
    )
    assert fn_error.get("Code") == "ValidationError", (
        f"an unknown intrinsic in Outputs must be ValidationError, got {fn_error.get('Code')!r}: "
        f"{fn_error.get('Message')!r}"
    )
    assert fn_error.get("Message") == BOGUS_FUNCTION_MESSAGE, (
        f"the rejection must NAME the unresolvable function {BOGUS_FUNCTION!r}: expected "
        f"{BOGUS_FUNCTION_MESSAGE!r}, got {fn_error.get('Message')!r}"
    )

    # --- Beat 3: a resolvable intrinsic over an absent mapping key is refused --------------------
    bad_map_body = _template_with_output({"Fn::FindInMap": ["EnvMap", MISSING_MAP_KEY, "size"]})
    bad_map_stack = ctx.unique_name("sim2real-cfn-outres-map-")
    map_error = _client_error(
        lambda: cf.create_stack(StackName=bad_map_stack, TemplateBody=bad_map_body)
    )
    assert map_error.get("Code") == "ValidationError", (
        f"a FindInMap over an absent key must be ValidationError, got {map_error.get('Code')!r}: "
        f"{map_error.get('Message')!r}"
    )
    assert map_error.get("Message") == MISSING_MAP_KEY_MESSAGE, (
        f"the rejection must NAME the mapping it could not resolve: expected "
        f"{MISSING_MAP_KEY_MESSAGE!r}, got {map_error.get('Message')!r}"
    )

    # --- Beat 4: both are Outputs-RESOLUTION failures, visible to the structure layer ------------
    for label, body, expected in (
        ("unknown-intrinsic", bogus_fn_body, BOGUS_FUNCTION_MESSAGE),
        ("absent-mapping-key", bad_map_body, MISSING_MAP_KEY_MESSAGE),
    ):
        error = _client_error(lambda b=body: cf.validate_template(TemplateBody=b))
        got = (error.get("Code"), error.get("Message"))
        assert got == ("ValidationError", expected), (
            f"ValidateTemplate must also refuse the {label} body -- resolving Outputs needs no "
            f"resource schema -- expected ('ValidationError', {expected!r}), got {got!r}"
        )

    # --- Beat 5: effect-absent -- neither refusal left a stack behind ----------------------------
    for stack_name in (bogus_fn_stack, bad_map_stack):
        error = _client_error(lambda n=stack_name: cf.describe_stacks(StackName=n))
        assert error.get("Code") == "ValidationError", (
            f"a refused CreateStack must leave no stack named {stack_name!r}; describe_stacks gave "
            f"{error.get('Code')!r}"
        )
        assert error.get("Message") == f"Stack with id {stack_name} does not exist", (
            f"expected a not-found message for {stack_name!r}, got {error.get('Message')!r}"
        )


def _base(outputs: dict) -> str:
    """One WaitConditionHandle (the cheapest real resource type that needs no properties and no
    backing service) plus a Mappings block, so every body differs only in the Outputs under test."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Mappings": {"EnvMap": {"dev": {"size": "small"}, "prod": {"size": "large"}}},
            "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
            "Outputs": outputs,
        }
    )


def _resolvable_template() -> str:
    return _base(
        {
            "Mapped": {"Value": {"Fn::FindInMap": ["EnvMap", "prod", "size"]}},
            "Joined": {"Value": {"Fn::Join": ["-", JOIN_PARTS]}},
        }
    )


def _template_with_output(value: dict) -> str:
    """The control's two outputs, with the SECOND one replaced by the unresolvable value under test.
    Keeping the resolvable sibling in place is deliberate: it is what makes 'the whole stack is
    refused' distinguishable from 'the bad output alone is dropped'."""
    return _base(
        {
            "Mapped": {"Value": {"Fn::FindInMap": ["EnvMap", "prod", "size"]}},
            "Unresolvable": {"Value": value},
        }
    )


def _client_error(fn) -> dict:
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_stack(cf, stack_name: str) -> dict:
    """Poll DescribeStacks to a create-terminal state; return the whole stack dict. RAISES on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_name)["Stacks"][0]
        if last["StackStatus"] in _CREATE_TERMINAL:
            return last
        time.sleep(4.0)
    last_status = last.get("StackStatus") if last else None
    raise AssertionError(
        f"stack {stack_name!r} did not reach a create-terminal state within {STACK_TIMEOUT_S}s "
        f"(last={last_status!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
