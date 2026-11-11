"""delete-nonexistent-subnet-group."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-subnet-group"
GROUP = 'subnet_groups'
SERVICES = ['rds']

ERR_DB_SUBNET_GROUP_NOT_FOUND = "DBSubnetGroupNotFoundFault"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _client_error(fn):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _delete_subnet_group_quietly(rds, name):
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != ERR_DB_SUBNET_GROUP_NOT_FOUND:
            raise


def _delete_with_retry(fn, timeout_s=300, interval_s=15):
    """Run an EC2 delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _own_subnet_ids(ctx, count=2):
    """Subnet ids in *count* distinct AZs of a VPC this check creates, registered for cleanup."""
    ec2 = ctx.client("ec2")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= count, f"region {ctx.region!r} has only {len(azs)} available AZ(s)"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.195.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.195.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid))
        )
        subnet_ids.append(subnet_id)
    return subnet_ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBSubnetGroup on a nonexistent name fails DBSubnetGroupNotFoundFault.

    A freshly created group deletes fine first, so the rejection is specific to the missing name.
    """
    rds = ctx.client("rds")

    subnet_ids = _own_subnet_ids(ctx)
    control_name = ctx.unique_name("sim2real-behav-sng-ctrl-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=control_name,
        DBSubnetGroupDescription="sim2real positive control",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_subnet_group_quietly(rds, control_name))
    rds.delete_db_subnet_group(DBSubnetGroupName=control_name)
    control_code, control_msg = _client_error(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=control_name)
    )
    assert control_code == ERR_DB_SUBNET_GROUP_NOT_FOUND, (
        f"control group should be gone, got code={control_code!r}"
    )
    assert control_msg == f"DB Subnet group '{control_name}' not found.", control_msg

    ghost = ctx.unique_name("sim2real-behav-sng-ghost-")
    # Delete and Describe word the not-found message differently ("subnet" vs "Subnet").
    code, msg = _client_error(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=ghost))
    assert code == ERR_DB_SUBNET_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_SUBNET_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert msg == f"DB subnet group '{ghost}' does not exist.", msg

    read_code, read_msg = _client_error(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=ghost)
    )
    assert read_code == ERR_DB_SUBNET_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_SUBNET_GROUP_NOT_FOUND} on independent read, got {read_code!r}"
    )
    assert read_msg == f"DB Subnet group '{ghost}' not found.", read_msg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
