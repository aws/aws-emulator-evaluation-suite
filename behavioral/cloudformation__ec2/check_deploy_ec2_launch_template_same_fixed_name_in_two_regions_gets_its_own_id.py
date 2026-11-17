"""deploy-ec2-launch-template-same-fixed-name-in-two-regions-gets-its-own-id."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ec2-launch-template-same-fixed-name-in-two-regions-gets-its-own-id"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]


def _second_region(region: str) -> str:
    """A commercial Region other than ``region``, chosen deterministically."""
    return "us-east-1" if region != "us-east-1" else "us-west-2"


_CHEAP_CANDIDATES = ("t3.nano", "t3.micro", "t2.nano", "t2.micro")


def _cheapest_in_region(ec2) -> str:
    """The cheapest of ``_CHEAP_CANDIDATES`` DescribeInstanceTypeOfferings reports for this
    client's Region."""
    offered = {
        o["InstanceType"]
        for o in ec2.describe_instance_type_offerings(LocationType="region")[
            "InstanceTypeOfferings"
        ]
    }
    for candidate in _CHEAP_CANDIDATES:
        if candidate in offered:
            return candidate
    raise AssertionError(
        f"none of {_CHEAP_CANDIDATES!r} is offered in region {ec2.meta.region_name!r}"
    )


def _template(name: str, instance_type: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Lt": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateName": name,
                    "LaunchTemplateData": {"InstanceType": instance_type},
                },
            },
        },
        "Outputs": {"LaunchTemplateId": {"Value": {"Ref": "Lt"}}},
    }


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_create(ctx, cfn, stack_id: str, cap_s: float = 300.0) -> dict[str, Any]:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} settling: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {cap_s:.0f}s"
            )
        time.sleep(3)


def _delete_stack_and_wait(cfn, stack_id: str, timeout_s: float = 300.0) -> None:
    """Delete the stack by id, whatever its state, and wait for DELETE_COMPLETE; anything else
    raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    while final["StackStatus"] not in ("DELETE_COMPLETE", "DELETE_FAILED"):
        if time.monotonic() > deadline:
            break
        time.sleep(3)
        final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN launch template under one fixed LaunchTemplateName, deployed by separate stacks in
    two Regions of one account, gets its own LaunchTemplateId in each Region, and each Region
    lists exactly its own template under that name.
    """
    name = ctx.unique_name("sim2real-xsvc-ltregion-")
    results: list[tuple[str, str]] = []
    for region in (ctx.region, _second_region(ctx.region)):
        cfn = ctx.client("cloudformation", region=region)
        ec2 = ctx.client("ec2", region=region)
        instance_type = _cheapest_in_region(ec2)

        stack_name = ctx.unique_name("sim2real-xsvc-ltregionstack-")
        stack_id = cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(_template(name, instance_type)),
            Tags=[{"Key": "sim2real", "Value": stack_name}],
        )["StackId"]
        ctx.on_cleanup(lambda cfn=cfn, stack_id=stack_id: _delete_stack_and_wait(cfn, stack_id))

        stack = _wait_create(ctx, cfn, stack_id)
        assert stack["StackStatus"] == "CREATE_COMPLETE", (
            f"stack in {region!r} ended {stack['StackStatus']!r} "
            f"({stack.get('StackStatusReason')!r}), expected 'CREATE_COMPLETE'"
        )
        outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        lt_id = outputs["LaunchTemplateId"]

        lt = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
        assert lt["LaunchTemplateName"] == name, (
            f"EC2 in {region!r} reports launch template name {lt['LaunchTemplateName']!r}, "
            f"expected {name!r}"
        )
        results.append((region, lt_id))

    for region, lt_id in results:
        ec2 = ctx.client("ec2", region=region)
        by_name = [
            (t["LaunchTemplateId"], t["LaunchTemplateName"])
            for t in ec2.describe_launch_templates(LaunchTemplateNames=[name])["LaunchTemplates"]
        ]
        assert by_name == [(lt_id, name)], (
            f"DescribeLaunchTemplates by name {name!r} in {region!r} lists {by_name!r}, expected "
            f"exactly {[(lt_id, name)]!r}"
        )
    (region_a, id_a), (region_b, id_b) = results
    assert id_a != id_b, (
        f"the same LaunchTemplateName {name!r} in two regions of one account got the same "
        f"LaunchTemplateId {id_a!r} in both {region_a!r} and {region_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
