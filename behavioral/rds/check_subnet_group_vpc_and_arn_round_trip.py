"""subnet-group-vpc-and-arn-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-vpc-and-arn-round-trip"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VpcId and DBSubnetGroupArn on a newly created DB subnet group are byte-identical
    across repeated DescribeDBSubnetGroups calls -- not regenerated or recomputed per read."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx, ec2)

    group_name = ctx.unique_name("sim2real-subnetgrp-")
    created = _create_subnet_group_once_visible(rds, group_name, subnet_ids)
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group_name))

    assert created["VpcId"] == vpc_id, (
        f"VpcId on create: expected {vpc_id!r}, got {created['VpcId']!r}"
    )
    first_arn = created["DBSubnetGroupArn"]
    assert first_arn, "DBSubnetGroupArn was empty on create"

    for _ in range(2):
        described = rds.describe_db_subnet_groups(DBSubnetGroupName=group_name)["DBSubnetGroups"][
            0
        ]
        assert described["VpcId"] == vpc_id, (
            f"VpcId drifted: expected {vpc_id!r}, got {described['VpcId']!r}"
        )
        assert described["DBSubnetGroupArn"] == first_arn, (
            f"ARN drifted: expected {first_arn!r}, got {described['DBSubnetGroupArn']!r}"
        )
        time.sleep(1)


def _create_subnet_group_once_visible(rds, group_name: str, subnet_ids: list[str]) -> dict:
    """RDS's own AZ-coverage check reads the subnets through EC2 and can lag their creation
    by a few seconds -- a freshly-created subnet is not an eventual-consistency risk to the
    caller, but RDS resolving its AZ from EC2 genuinely is. Retry only on that specific error,
    for a deadline, never unconditionally."""
    deadline = time.monotonic() + 30
    while True:
        try:
            return rds.create_db_subnet_group(
                DBSubnetGroupName=group_name,
                DBSubnetGroupDescription="sim2real subnet group VPC/ARN round-trip",
                SubnetIds=subnet_ids,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )["DBSubnetGroup"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBSubnetGroupDoesNotCoverEnoughAZs":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "RDS still cannot see 2-AZ coverage for freshly created subnets "
                    f"{subnet_ids} after 30s"
                ) from exc
            time.sleep(3)


def _create_vpc_and_subnets(ctx, ec2) -> tuple[str, list[str]]:
    """Create a fresh VPC with subnets in 2 distinct AZs -- no dependence on an ambient
    default VPC, which a freshly provisioned account may not have."""
    azs = sorted(
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    if len(azs) < 2:
        raise AssertionError(
            f"region {ctx.region!r} has fewer than 2 available standard AZs: {azs}"
        )

    tag_spec = [{"Key": "sim2real:managed", "Value": "true"}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.198.0.{i * 128}/25",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: ec2.delete_subnet(SubnetId=subnet_id))
        subnet_ids.append(subnet_id)

    ec2.get_waiter("subnet_available").wait(SubnetIds=subnet_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id, subnet_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
