"""delete-subnet-group-in-use."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "delete-subnet-group-in-use"
GROUP = 'subnet_groups'
SERVICES = ['rds']

ERR_INVALID_SUBNET_GROUP_STATE = "InvalidDBSubnetGroupStateFault"


_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _client_error(fn, what="the call"):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} was expected to fail but it SUCCEEDED: {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _instance_present(rds, ident):
    try:
        rds.describe_db_instances(DBInstanceIdentifier=ident)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
            return False
        raise
    return True


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=2, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# One window for all network deletes: RDS releases the instance's network interfaces
# minutes after DeleteDBInstance completes.
_NET_TEARDOWN_S = 900
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id"}


def _delete_net(ec2, window, op, interval_s=2, **ident):
    """Wait for network interfaces in the resource to go, then delete it, retrying
    DependencyViolation until the shared deadline."""
    deadline = window.setdefault("deadline", time.monotonic() + _NET_TEARDOWN_S)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items()]
    while ec2.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]:
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    while True:
        try:
            getattr(ec2, op)(**ident)
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
        CidrBlock="10.197.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    window = {}
    ctx.on_cleanup(lambda: _delete_net(ec2, window, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.197.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, window, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBSubnetGroup on a group used by a live instance fails InvalidDBSubnetGroupStateFault.

    The group survives unchanged; once the instance is deleted the same call removes the group.
    """
    rds = ctx.client("rds")
    subnet_ids = _own_subnet_ids(ctx, count=2)
    name = ctx.unique_name("sim2real-behav-subg-inuse-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="behavioral check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup_subnet_group():
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DBSubnetGroupNotFoundFault":
                raise

    ctx.on_cleanup(_cleanup_subnet_group)

    ident = ctx.unique_name("sim2real-behav-dbi-")
    rds.create_db_instance(
        DBInstanceIdentifier=ident,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2Real#Pass99",
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        DBSubnetGroupName=name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup_instance():
        # Wait until the instance is gone so the subnet group and network deletes can follow.
        deadline = time.monotonic() + 900
        while True:
            try:
                status = rds.describe_db_instances(DBInstanceIdentifier=ident)["DBInstances"][0][
                    "DBInstanceStatus"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                    return
                raise
            if status == "deleting":
                break
            try:
                rds.delete_db_instance(
                    DBInstanceIdentifier=ident, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                    return
                if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        _poll_until(lambda: _instance_present(rds, ident), lambda present: not present,
                    timeout_s=1200, description=f"instance {ident} deleted")

    ctx.on_cleanup(_cleanup_instance)

    inst = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=ident)["DBInstances"][0],
        lambda i: i.get("DBInstanceStatus") == "available",
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        ctx=ctx,
        description=f"instance {ident} available",
    )
    assert inst["DBInstanceStatus"] == "available", (
        f"instance {ident} should be available before the negative, "
        f"got {inst['DBInstanceStatus']!r}"
    )

    code, msg = _client_error(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        what="DeleteDBSubnetGroup while an instance is attached",
    )
    assert code == ERR_INVALID_SUBNET_GROUP_STATE, f"unexpected error code: {code!r}"
    assert msg == (
        f"Cannot delete the subnet group '{name}' because at least one database instance: "
        f"{ident} is still using it."
    ), msg

    still_there = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"][0]
    assert still_there["DBSubnetGroupName"] == name, (
        f"subnet group {name} should still exist after the rejected delete, "
        f"describe returned {still_there!r}"
    )
    assert {s["SubnetIdentifier"] for s in still_there["Subnets"]} == set(subnet_ids), (
        f"subnet group {name} subnets changed after the rejected delete: "
        f"{still_there['Subnets']!r}"
    )

    rds.delete_db_instance(
        DBInstanceIdentifier=ident, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
    _poll_until(lambda: _instance_present(rds, ident), lambda present: not present,
                timeout_s=_budget_s(ctx, 1800), ctx=ctx, description=f"instance {ident} deleted")
    gone_code, gone_msg = _client_error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=ident),
        what="DescribeDBInstances on the deleted instance",
    )
    assert gone_code == "DBInstanceNotFound", (
        f"instance {ident} should be fully gone after delete, describe returned "
        f"code={gone_code!r}"
    )
    assert gone_msg == f"DBInstance {ident} not found.", gone_msg

    rds.delete_db_subnet_group(DBSubnetGroupName=name)
    final_code, final_msg = _client_error(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=name),
        what="DescribeDBSubnetGroups on the deleted group",
    )
    assert final_code == "DBSubnetGroupNotFoundFault", (
        f"subnet group {name} should be gone once the instance is removed, describe returned "
        f"code={final_code!r}"
    )
    assert final_msg == f"DB Subnet group '{name}' not found.", final_msg

    mutate_code, mutate_msg = _client_error(
        lambda: rds.modify_db_subnet_group(DBSubnetGroupName=name, SubnetIds=subnet_ids),
        what="ModifyDBSubnetGroup on the deleted group",
    )
    assert mutate_code == "DBSubnetGroupNotFoundFault", (
        f"a mutation on the deleted subnet group {name} should fail with "
        f"DBSubnetGroupNotFoundFault, got {mutate_code!r}"
    )
    assert mutate_msg == f"DB subnet group '{name}' does not exist.", mutate_msg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
