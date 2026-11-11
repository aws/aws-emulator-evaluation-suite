"""parameter-constraint-description-on-number-and-allowed-values."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-constraint-description-on-number-and-allowed-values"
GROUP = "stack_parameters"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_RANGE_HINT = "Pick a size from 2 to 8."
_ENV_HINT = "Env is prod or dev."

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "Size": {"Type": "Number", "MinValue": 2, "MaxValue": 8, "ConstraintDescription": _RANGE_HINT},
        "Count": {"Type": "Number", "MinValue": 2, "MaxValue": 8},
        "Env": {"Type": "String", "AllowedValues": ["prod", "dev"], "ConstraintDescription": _ENV_HINT},
        "Tier": {"Type": "String", "AllowedValues": ["gold", "silver"]},
    },
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {"Echo": {"Value": {"Fn::Join": ["/", [
        {"Ref": "Size"}, {"Ref": "Count"}, {"Ref": "Env"}, {"Ref": "Tier"}]]}}},
})

_GOOD = {"Size": "2", "Count": "8", "Env": "dev", "Tier": "gold"}


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


def _params(**values: str) -> list:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in {**_GOOD, **values}.items()]


def _refused(ctx, cf, params: list):
    """(code, message) of a CreateStack that must be refused, and proof no stack was made."""
    name = ctx.unique_name("sim2real-behav-cdnum-bad-")
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
    """MinValue, MaxValue and AllowedValues refusals carry the ConstraintDescription when one is
    declared and their own default message when not; the boundary values deploy.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html
    """
    cf = ctx.client("cloudformation")

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-cdnum-ok-"), TemplateBody=_TEMPLATE,
                               Parameters=_params(), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"boundary values must deploy; got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    assert stack["Outputs"][0]["OutputValue"] == "2/8/dev/gold", f"outputs: {stack['Outputs']!r}"

    cases = (
        ("Size below MinValue", {"Size": "1"}, f"Parameter Size failed to satisfy constraint: {_RANGE_HINT}"),
        ("Size above MaxValue", {"Size": "9"}, f"Parameter Size failed to satisfy constraint: {_RANGE_HINT}"),
        ("Count below MinValue", {"Count": "1"}, "Parameter 'Count' must be a number not less than 2"),
        ("Count above MaxValue", {"Count": "9"}, "Parameter 'Count' must be a number not greater than 8"),
        ("Env outside AllowedValues", {"Env": "test"}, f"Parameter Env failed to satisfy constraint: {_ENV_HINT}"),
        ("Tier outside AllowedValues", {"Tier": "bronze"}, "Parameter 'Tier' must be one of AllowedValues"),
    )
    for label, values, message in cases:
        got = _refused(ctx, cf, _params(**values))
        assert got == ("ValidationError", message), f"{label}: got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
