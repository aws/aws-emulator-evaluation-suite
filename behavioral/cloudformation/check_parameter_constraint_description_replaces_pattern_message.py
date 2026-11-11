"""parameter-constraint-description-replaces-pattern-message."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-constraint-description-replaces-pattern-message"
GROUP = "stack_parameters"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_PATTERN = "^[a-z]+$"
_HINT = "Use lowercase letters only."

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "Described": {"Type": "String", "AllowedPattern": _PATTERN, "ConstraintDescription": _HINT},
        "Plain": {"Type": "String", "AllowedPattern": _PATTERN},
    },
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {"Echo": {"Value": {"Fn::Join": ["/", [{"Ref": "Described"}, {"Ref": "Plain"}]]}}},
})


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


def _params(described: str, plain: str) -> list:
    return [{"ParameterKey": "Described", "ParameterValue": described},
            {"ParameterKey": "Plain", "ParameterValue": plain}]


def _refused(ctx, cf, params: list):
    """(code, message) of a CreateStack that must be refused, and proof no stack was made."""
    name = ctx.unique_name("sim2real-behav-cdesc-bad-")
    try:
        stack_id = cf.create_stack(StackName=name, TemplateBody=_TEMPLATE, Parameters=params, Tags=_TAGS)["StackId"]
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    else:
        ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
        raise AssertionError(f"CreateStack with {params!r} was accepted as {stack_id}")
    try:
        cf.describe_stacks(StackName=name)
    except ClientError as exc:
        gone = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    else:
        raise AssertionError(f"a refused create left stack {name}")
    assert gone == ("ValidationError", f"Stack with id {name} does not exist"), f"DescribeStacks gave {gone!r}"
    return got


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A value that misses AllowedPattern is refused with the ConstraintDescription text when one is
    declared and with the default pattern message when not; conforming values deploy.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html
    """
    cf = ctx.client("cloudformation")

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-cdesc-ok-"), TemplateBody=_TEMPLATE,
                               Parameters=_params("good", "fine"), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    assert stack["Outputs"][0]["OutputValue"] == "good/fine", f"outputs: {stack['Outputs']!r}"

    got = _refused(ctx, cf, _params("Bad1", "fine"))
    assert got == ("ValidationError", f"Parameter Described failed to satisfy constraint: {_HINT}"), (
        f"with ConstraintDescription: got {got!r}"
    )
    got = _refused(ctx, cf, _params("good", "Bad1"))
    assert got == ("ValidationError", f"Parameter 'Plain' must match pattern {_PATTERN}"), (
        f"without ConstraintDescription: got {got!r}"
    )

    code, msg = None, None
    try:
        cf.update_stack(StackName=stack_id, UsePreviousTemplate=True, Parameters=_params("Bad1", "fine"))
    except ClientError as exc:
        code, msg = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    assert (code, msg) == ("ValidationError", f"Parameter Described failed to satisfy constraint: {_HINT}"), (
        f"UpdateStack must refuse the same way; got {(code, msg)!r}"
    )
    after = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    values = {p["ParameterKey"]: p["ParameterValue"] for p in after["Parameters"]}
    assert (after["StackStatus"], values) == ("CREATE_COMPLETE", {"Described": "good", "Plain": "fine"}), (
        f"a refused update must leave the stack as it was: {after['StackStatus']!r} {values!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
