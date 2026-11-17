"""cfn-ssm-parameter-securestring-type-update-rejected-value-intact."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-securestring-type-update-rejected-value-intact"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_STACK_S = 600.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(name: str, param_type: str, value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name, "Type": param_type, "Value": value},
            },
        },
    })


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, *, cap_s: float = _STACK_S) -> dict:
    """Poll DescribeStacks by StackId until no operation is in progress."""
    deadline = time.monotonic() + cap_s
    while True:
        stack = _stack(cfn, stack_id)
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {cap_s:.0f}s")
        time.sleep(3.0)


def _delete_stack(cfn, stack_id: str) -> None:
    """DeleteStack by id and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _STACK_S
    while True:
        stack = _stack(cfn, stack_id)
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} delete ended {stack['StackStatus']!r}: "
                f"{stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


_VALIDATION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN update that retypes an AWS::SSM::Parameter to SecureString is accepted by UpdateStack
    but fails template validation before touching the resource, and the parameter keeps the
    String value the prior, successful deploy wrote.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-parameter.html
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    name = ctx.unique_name("sim2real-behav-ssmsecstr-")
    stack_name = ctx.unique_name("sim2real-behav-ssmsecstr-")

    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(name, "String", "plain-value"), Tags=_TAGS,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    created = _settle(cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    control = ssm.get_parameter(Name=name)["Parameter"]
    assert (control["Type"], control["Value"], control["Version"]) == ("String", "plain-value", 1), (
        f"the control deploy must land as a plain String parameter at version 1, got {control!r}"
    )

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(name, "SecureString", "secret-value"))
    updated = _settle(cfn, stack_id, cap_s=_STACK_S)
    assert updated["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"a SecureString retype must roll the stack back, got {updated['StackStatus']!r}: "
        f"{updated.get('StackStatusReason')!r}"
    )

    new_events = _events(cfn, stack_id)[before:]
    failed = [e for e in new_events if e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one UPDATE_FAILED event, got {failed!r}"
    assert failed[0]["ResourceStatusReason"] == _VALIDATION_REASON, failed[0]["ResourceStatusReason"]
    touched = {e["LogicalResourceId"] for e in new_events if e["LogicalResourceId"] == "Param"}
    assert touched == set(), (
        f"the resource handler must never run for a template that fails validation, saw "
        f"events for Param: {touched!r}"
    )

    after = ssm.get_parameter(Name=name)["Parameter"]
    assert (after["Type"], after["Value"], after["Version"]) == ("String", "plain-value", 1), (
        f"the rejected update must leave the parameter exactly as the control deploy wrote it, "
        f"got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
