"""template-init-metadata-round-trips-describe-stack-resource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "template-init-metadata-round-trips-describe-stack-resource"
GROUP = "metadata"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _init(version: str) -> dict:
    return {
        "AWS::CloudFormation::Init": {
            "configSets": {"default": ["base", "app"]},
            "base": {"files": {"/etc/app.conf": {"content": {"Fn::Sub": "stack=${AWS::StackName}"}, "mode": "000644"}}},
            "app": {"commands": {"01-start": {"command": f"echo {version}"}}},
        },
    }


def _template(version: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle", "Metadata": _init(version)}},
    })


def _expected(version: str, stack_name: str) -> dict:
    meta = _init(version)
    meta["AWS::CloudFormation::Init"]["base"]["files"]["/etc/app.conf"]["content"] = f"stack={stack_name}"
    return meta


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


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStackResource returns a resource's AWS::CloudFormation::Init metadata with intrinsics
    resolved, and a metadata-only update replaces it without touching the resource's physical id.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-init.html
    """
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-init-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=_template("v1"), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    before = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Handle")["StackResourceDetail"]
    assert json.loads(before["Metadata"]) == _expected("v1", name), f"Metadata after create: {before['Metadata']!r}"

    cf.update_stack(StackName=stack_id, TemplateBody=_template("v2"))
    updated = _settle(cf, stack_id, start="CREATE_COMPLETE")
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"a metadata-only update must apply; got {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    after = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Handle")["StackResourceDetail"]
    assert json.loads(after["Metadata"]) == _expected("v2", name), f"Metadata after update: {after['Metadata']!r}"
    assert after["PhysicalResourceId"] == before["PhysicalResourceId"], (
        f"a metadata-only update replaced the handle: {before['PhysicalResourceId']!r} -> {after['PhysicalResourceId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
