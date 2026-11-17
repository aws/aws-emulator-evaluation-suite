"""resource-type-filter-scopes-ec2-tag-discovery-by-type."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-type-filter-scopes-ec2-tag-discovery-by-type"
GROUP = "tagging-discovery"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResources' ResourceTypeFilters partitions by EC2 resource type: a VPC and a security
    group sharing one tag value stay isolated from each other's type filter, and a type filter
    naming neither resource's type returns nothing, not the tag-matched union.
    """
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    shared_key = ctx.unique_name("sim2real-behav-leak-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": shared_key, "Value": "shared"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    vpc_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real " + CHECK,
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": shared_key, "Value": "shared"}]}],
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound"))
    sg_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:security-group/{sg_id}"

    both = _poll_until(
        lambda: {
            m["ResourceARN"]
            for m in rgt.get_resources(
                TagFilters=[{"Key": shared_key, "Values": ["shared"]}],
            )["ResourceTagMappingList"]
        },
        lambda arns: arns == {vpc_arn, sg_arn},
        timeout_s=120.0,
    )
    assert both == {vpc_arn, sg_arn}, (
        f"positive control: an UNFILTERED query for the shared tag matched {sorted(both)!r}, "
        f"expected both the VPC and the security group -- without this, a narrower result below "
        f"proves nothing about the type filter"
    )

    vpc_only = {
        m["ResourceARN"]
        for m in rgt.get_resources(
            ResourceTypeFilters=["ec2:vpc"],
            TagFilters=[{"Key": shared_key, "Values": ["shared"]}],
        )["ResourceTagMappingList"]
    }
    assert vpc_only == {vpc_arn}, (
        f"ResourceTypeFilters=['ec2:vpc'] matched {sorted(vpc_only)!r}; the security group "
        f"leaked across the type filter despite sharing only the tag, not the type"
    )

    sg_only = {
        m["ResourceARN"]
        for m in rgt.get_resources(
            ResourceTypeFilters=["ec2:security-group"],
            TagFilters=[{"Key": shared_key, "Values": ["shared"]}],
        )["ResourceTagMappingList"]
    }
    assert sg_only == {sg_arn}, (
        f"ResourceTypeFilters=['ec2:security-group'] matched {sorted(sg_only)!r}; the VPC "
        f"leaked across the type filter despite sharing only the tag, not the type"
    )

    unrelated = {
        m["ResourceARN"]
        for m in rgt.get_resources(
            ResourceTypeFilters=["ec2:subnet"],
            TagFilters=[{"Key": shared_key, "Values": ["shared"]}],
        )["ResourceTagMappingList"]
    }
    assert unrelated == set(), (
        f"ResourceTypeFilters=['ec2:subnet'] matched {sorted(unrelated)!r}; a type filter naming "
        f"neither tagged resource's type must return nothing, not the tag-matched union"
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
