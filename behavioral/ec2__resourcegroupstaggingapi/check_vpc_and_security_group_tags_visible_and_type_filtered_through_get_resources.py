"""vpc-and-security-group-tags-visible-and-type-filtered-through-get-resources."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vpc-and-security-group-tags-visible-and-type-filtered-through-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags set at creation on an EC2 VPC and a security group are both found by GetResources,
    ResourceTypeFilters separates ec2:vpc from ec2:security-group, and omitting it widens the
    query back to both.
    """
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": key, "Value": value}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    vpc_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    sg_name = ctx.unique_name("sim2real-behav-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real tagging-discovery security group",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": key, "Value": value}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    sg_arn = sg["SecurityGroupArn"]

    both = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["ec2:vpc", "ec2:security-group"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: {m["ResourceARN"] for m in mappings} == {vpc_arn, sg_arn},
        timeout_s=120.0,
    )
    both_arns = {m["ResourceARN"] for m in both}
    assert both_arns == {vpc_arn, sg_arn}, (
        f"tag filter {key}={value!r} with ResourceTypeFilters=[ec2:vpc, ec2:security-group] "
        f"returned {sorted(both_arns)!r}, expected exactly the vpc {vpc_arn!r} and the security "
        f"group {sg_arn!r}"
    )

    vpc_only = rgt.get_resources(
        ResourceTypeFilters=["ec2:vpc"], TagFilters=[{"Key": key, "Values": [value]}]
    )["ResourceTagMappingList"]
    vpc_only_arns = {m["ResourceARN"] for m in vpc_only}
    assert vpc_only_arns == {vpc_arn}, (
        f"ResourceTypeFilters=[ec2:vpc] returned {sorted(vpc_only_arns)!r}, expected exactly "
        f"the vpc {vpc_arn!r} and NOT the security group"
    )

    sg_only = rgt.get_resources(
        ResourceTypeFilters=["ec2:security-group"], TagFilters=[{"Key": key, "Values": [value]}]
    )["ResourceTagMappingList"]
    sg_only_arns = {m["ResourceARN"] for m in sg_only}
    assert sg_only_arns == {sg_arn}, (
        f"ResourceTypeFilters=[ec2:security-group] returned {sorted(sg_only_arns)!r}, expected "
        f"exactly the security group {sg_arn!r} and NOT the vpc"
    )

    # Omitting ResourceTypeFilters widens the same tag query back to every matching type.
    unfiltered = rgt.get_resources(TagFilters=[{"Key": key, "Values": [value]}])[
        "ResourceTagMappingList"
    ]
    unfiltered_arns = {m["ResourceARN"] for m in unfiltered}
    assert unfiltered_arns == {vpc_arn, sg_arn}, (
        f"GetResources with no ResourceTypeFilters returned {sorted(unfiltered_arns)!r} for "
        f"{key}={value!r}, expected both the vpc {vpc_arn!r} and the security group {sg_arn!r}"
    )


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
