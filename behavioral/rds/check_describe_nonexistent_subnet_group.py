"""describe-nonexistent-subnet-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-subnet-group"
GROUP = 'subnet_groups'
SERVICES = ['rds']

ERR_DB_SUBNET_GROUP_NOT_FOUND = "DBSubnetGroupNotFoundFault"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBSubnetGroups with a nonexistent name raises DBSubnetGroupNotFoundFault, while
    the identical call against a real subnet group succeeds as the positive control -- so a
    target that answers NotFound for every name, not only an absent one, fails this too."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    subnet_ids = _create_isolated_subnets(ctx, ec2, count=2)
    name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real describe-nonexistent-subnet-group positive control",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))

    # positive control: the real group is found by its own name
    groups = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"]
    assert len(groups) == 1 and groups[0]["DBSubnetGroupName"] == name, (
        f"positive control: expected exactly one subnet group named {name!r}, got {groups!r}"
    )

    # negative: a name that was never created raises the specific NotFound fault
    ghost = ctx.unique_name("sim2real-behav-sng-ghost-")
    err = _rejection(lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=ghost))
    assert err.get("Code") == ERR_DB_SUBNET_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_SUBNET_GROUP_NOT_FOUND}, got {err}"
    )
    assert err.get("Message") == f"DB Subnet group '{ghost}' not found.", (
        f"unexpected {ERR_DB_SUBNET_GROUP_NOT_FOUND} message: {err}"
    )


def _create_isolated_subnets(ctx, ec2, count: int = 2) -> list[str]:
    """A fresh VPC with `count` subnets in distinct AZs, sized for a DBSubnetGroup. Self-contained
    so the check does not depend on an ambient default VPC that a freshly provisioned account may
    not have."""
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"][:count]
    ]
    if len(azs) < count:
        raise AssertionError(f"region {ctx.region} has fewer than {count} available AZs")

    tags = [{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "true"}]}]
    vpc_id = ec2.create_vpc(CidrBlock="10.199.0.0/24", TagSpecifications=tags)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_tags = [{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "true"}]}]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.199.0.{i * 128}/25",
            AvailabilityZone=az,
            TagSpecifications=subnet_tags,
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
