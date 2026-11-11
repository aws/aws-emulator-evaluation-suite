"""intrinsic-novalue-on-update-does-not-clear-ssm-property."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "intrinsic-novalue-on-update-does-not-clear-ssm-property"
GROUP = "intrinsics"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_DESCRIPTION = "sim2real described parameter"
_PATTERN = "^[a-z]+$"


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Describe": {"Type": "String", "AllowedValues": ["yes", "no"]}},
        "Conditions": {"Described": {"Fn::Equals": [{"Ref": "Describe"}, "yes"]}},
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": name,
                    "Type": "String",
                    "Value": "abc",
                    "Description": {"Fn::If": ["Described", _DESCRIPTION, {"Ref": "AWS::NoValue"}]},
                    "AllowedPattern": {"Fn::If": ["Described", _PATTERN, {"Ref": "AWS::NoValue"}]},
                },
            },
        },
    })


def _settle(cf, stack_id: str, start: str = "") -> dict:
    """Poll DescribeStacks by StackId until the status is neither *_IN_PROGRESS nor ``start``."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        if not status.endswith("_IN_PROGRESS") and status != start:
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


def _described(ssm, name: str) -> dict:
    found = ssm.describe_parameters(ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}])
    rows = found["Parameters"]
    assert [r["Name"] for r in rows] == [name], f"DescribeParameters for {name}: {rows!r}"
    return {k: rows[0].get(k) for k in ("Description", "AllowedPattern")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An update that turns two already-set properties into AWS::NoValue does not clear them from
    the live SSM parameter: both keep the value set at create time, the physical id is unchanged,
    and the stack still records the parameter as UPDATE_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/pseudo-parameter-reference.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-novalue-")
    body = _template(name)

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-novalue-"), TemplateBody=body, Tags=_TAGS,
                               Parameters=[{"ParameterKey": "Describe", "ParameterValue": "yes"}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    assert _described(ssm, name) == {"Description": _DESCRIPTION, "AllowedPattern": _PATTERN}, (
        f"with the condition true both properties are set; got {_described(ssm, name)!r}"
    )
    before = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Param")["StackResourceDetail"]

    cf.update_stack(StackName=stack_id, UsePreviousTemplate=True,
                    Parameters=[{"ParameterKey": "Describe", "ParameterValue": "no"}])
    updated = _settle(cf, stack_id, start="CREATE_COMPLETE")
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"got {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    assert _described(ssm, name) == {"Description": _DESCRIPTION, "AllowedPattern": _PATTERN}, (
        f"turning both properties into AWS::NoValue must not clear the live parameter: it must "
        f"still carry the values set at create time; got {_described(ssm, name)!r}"
    )
    after = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Param")["StackResourceDetail"]
    assert (after["PhysicalResourceId"], after["ResourceStatus"]) == (before["PhysicalResourceId"], "UPDATE_COMPLETE"), (
        f"the parameter must be updated in place; before {before['PhysicalResourceId']!r}, after {after!r}"
    )
    value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    assert value == "abc", f"the value must survive the update; got {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
