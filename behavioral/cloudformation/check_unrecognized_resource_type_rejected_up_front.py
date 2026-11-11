"""unrecognized-resource-type-rejected-up-front."""
# Unknown resource TYPE is a template-format error (ValidateTemplate refuses); unknown PROPERTY is
# a resource-schema error (ValidateTemplate accepts), see the resource-schema check.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unrecognized-resource-type-rejected-up-front"
GROUP = "template_validation"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 240.0
GOOD_TYPE = "AWS::CloudFormation::WaitConditionHandle"
BOGUS_TYPE = "AWS::Nonsense::Widget"
UNRECOGNIZED_MESSAGE = f"Template format error: Unrecognized resource types: [{BOGUS_TYPE}]"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack and ValidateTemplate both refuse an unknown resource type with a message naming
    it, the same template with a real type provisions, and no stack is created.
    """
    cf = ctx.client("cloudformation")

    # --- Beat 1: positive control -- the same template with a real type must provision ------------
    good_stack = ctx.unique_name("sim2real-cfn-badtype-good-")
    cf.create_stack(StackName=good_stack, TemplateBody=_template(GOOD_TYPE))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=good_stack))
    good = _poll_stack(cf, good_stack)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"positive control {good_stack!r} must reach CREATE_COMPLETE, got {good['StackStatus']!r} "
        f"({good.get('StackStatusReason')!r})"
    )
    good_resource = cf.describe_stack_resource(StackName=good_stack, LogicalResourceId="Thing")
    assert good_resource["StackResourceDetail"]["ResourceType"] == GOOD_TYPE, (
        f"the control must record the declared type {GOOD_TYPE!r}, got "
        f"{good_resource['StackResourceDetail']['ResourceType']!r}"
    )

    # --- Beat 2: the unknown type is refused, and the message names it ---------------------------
    bogus_body = _template(BOGUS_TYPE)
    bogus_stack = ctx.unique_name("sim2real-cfn-badtype-bad-")
    error = _client_error(lambda: cf.create_stack(StackName=bogus_stack, TemplateBody=bogus_body))
    assert error.get("Code") == "ValidationError", (
        f"an unrecognized resource type must be ValidationError, got {error.get('Code')!r}: "
        f"{error.get('Message')!r}"
    )
    message = error.get("Message")
    assert message == UNRECOGNIZED_MESSAGE, (
        f"the refusal must say the type is unrecognized and NAME it -- a generic ValidationError "
        f"would also be raised by a target that refuses every template; expected "
        f"{UNRECOGNIZED_MESSAGE!r}, got {message!r}"
    )

    # --- Beat 3: the template-FORMAT layer owns this error, so ValidateTemplate refuses too -------
    validate_error = _client_error(lambda: cf.validate_template(TemplateBody=bogus_body))
    assert validate_error.get("Code") == "ValidationError", (
        f"ValidateTemplate must refuse an unrecognized resource type (it is a template-format error, "
        f"not a resource-schema error), got {validate_error.get('Code')!r}"
    )
    assert validate_error.get("Message") == UNRECOGNIZED_MESSAGE, (
        f"ValidateTemplate's refusal must also name {BOGUS_TYPE!r}: expected "
        f"{UNRECOGNIZED_MESSAGE!r}, got {validate_error.get('Message')!r}"
    )
    # ...and it must ACCEPT the control body, or "refuses the bogus one" says nothing.
    validated = cf.validate_template(TemplateBody=_template(GOOD_TYPE))
    assert isinstance(validated.get("Parameters"), list), (
        f"ValidateTemplate must accept the control template, got {validated!r}"
    )

    # --- Beat 4: effect-absent -- the refusal was up front, not a create-then-rollback ------------
    describe = _client_error(lambda: cf.describe_stacks(StackName=bogus_stack))
    assert describe.get("Code") == "ValidationError", (
        f"a refused CreateStack must leave NO stack named {bogus_stack!r}; describe_stacks gave "
        f"{describe.get('Code')!r}: {describe.get('Message')!r}"
    )
    assert describe.get("Message") == f"Stack with id {bogus_stack} does not exist", (
        f"expected a not-found message for {bogus_stack!r}, got {describe.get('Message')!r}"
    )
    # A rolled-back stack is still listed by ListStacks with a ROLLBACK_COMPLETE summary, so the
    # absence is confirmed against the listing as well as against the by-name read.
    assert bogus_stack not in _stack_names(cf), (
        f"{bogus_stack!r} appears in ListStacks, so the template was accepted and then failed rather "
        f"than being refused up front"
    )


def _template(resource_type: str) -> str:
    """One resource with no properties, so the control and the negative differ in EXACTLY the Type
    string and a passing control is attributable to nothing else."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Thing": {"Type": resource_type}},
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


def _stack_names(cf) -> set[str]:
    """Every stack name including deleted/rolled-back ones, across all pages."""
    names: set[str] = set()
    for page in cf.get_paginator("list_stacks").paginate():
        for summary in page.get("StackSummaries", []) or []:
            names.add(summary["StackName"])
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
