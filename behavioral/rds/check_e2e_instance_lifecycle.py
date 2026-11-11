"""e2e-instance-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "e2e-instance-lifecycle"
GROUP = 'e2e_workflows'
SERVICES = ['rds']

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"
_MANAGED_TAGS = [{"Key": "sim2real", "Value": "true"}]

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_available(rds, inst_id, timeout_s=900, *, ctx) -> None:
    """Poll until a DB instance reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"DB instance {inst_id} available: the run budget ended first; not graded")
    raise AssertionError(f"DB instance {inst_id} available not met within {timeout_s}s")


def _await_enis_clear(ec2, subnet_id, timeout_s=900, interval_s=2):
    """Wait out RDS ENIs left in a subnet of this check's own VPC after the instance is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subnet {subnet_id} still has {len(enis)} ENI(s) after {timeout_s}s: "
                f"{[e['NetworkInterfaceId'] for e in enis]}"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, timeout_s=300, interval_s=2):
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


def _own_subnet_group(ctx):
    """A DB subnet group over a two-AZ VPC this check creates; all of it registered for cleanup."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= 2, f"region {ctx.region!r} has only {len(azs)} available AZ(s); need 2"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.194.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.194.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]

        def _drop_subnet(sid=subnet_id):
            _await_enis_clear(ec2, sid)
            _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_drop_subnet)
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_gone(rds, inst_id, timeout_s=1800, ctx=None) -> None:
    """Poll until DescribeDBInstances reports the instance not found; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=inst_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == ERR_DB_INSTANCE_NOT_FOUND:
                return
            raise
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"DB instance {inst_id} deleted: the run budget ended first; not graded")
    raise AssertionError(f"DB instance {inst_id} still visible {timeout_s}s after delete")


def _delete_instance(rds, inst_id) -> None:
    """Teardown: delete the instance with no final snapshot and wait until it is gone."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    except ClientError as exc:
        # InvalidDBInstanceState: the instance is already deleting; wait it out below.
        if exc.response["Error"]["Code"] not in (
            ERR_DB_INSTANCE_NOT_FOUND,
            "InvalidDBInstanceState",
        ):
            raise
    _wait_gone(rds, inst_id)


def _client_error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; AssertionError when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One instance in a VPC of its own: create, describe, endpoint, modify, stop, start, delete."""
    rds = ctx.client("rds")
    inst_id = ctx.unique_name("sim2real-behav-inst-")
    subnet_group = _own_subnet_group(ctx)
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=0,
        DBSubnetGroupName=subnet_group,
        PubliclyAccessible=False,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    # Describe immediately: identity fields are set from the request
    resp = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
    inst = resp["DBInstances"][0]
    assert inst["DBInstanceIdentifier"] == inst_id
    assert inst["Engine"] == "mysql"
    assert inst["DBInstanceClass"] == "db.t3.micro"
    assert inst["DBInstanceStatus"] in ("creating", "available", "backing-up")

    # Wait for available
    _wait_available(rds, inst_id, timeout_s=_budget_s(ctx, 900), ctx=ctx)

    # Verify endpoint structure
    resp = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
    inst = resp["DBInstances"][0]
    assert inst["DBInstanceStatus"] == "available"
    endpoint = inst.get("Endpoint")
    assert endpoint is not None, "Available instance has no Endpoint"
    assert "Address" in endpoint
    assert "Port" in endpoint and endpoint["Port"] > 0
    assert inst["Engine"] == "mysql"
    assert inst["EngineVersion"].startswith("8.0")
    assert inst["AllocatedStorage"] == 20
    assert inst["MasterUsername"] == "sim2real"
    assert inst["StorageEncrypted"] is False

    # Modify allocated storage
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id,
        AllocatedStorage=25,
        ApplyImmediately=True,
    )
    resp = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
    inst = resp["DBInstances"][0]
    pending = inst.get("PendingModifiedValues", {})
    assert inst.get("AllocatedStorage") == 25 or pending.get("AllocatedStorage") == 25, (
        f"Modify not reflected: storage={inst.get('AllocatedStorage')}, pending={pending}"
    )

    # Stop: the storage change keeps the instance busy for a while, and StopDBInstance refuses
    # with InvalidDBInstanceState until it settles, so the stop is retried within a bound.
    stop_deadline = time.monotonic() + _budget_s(ctx, 1800)
    while True:
        try:
            rds.stop_db_instance(DBInstanceIdentifier=inst_id)
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidDBInstanceState"
                or time.monotonic() >= stop_deadline
            ):
                if exc.response["Error"]["Code"] == "InvalidDBInstanceState" and _budget_spent(ctx):
                    raise TimeoutError(f"StopDBInstance {inst_id}: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    stop_s = _budget_s(ctx, 600)
    deadline = time.monotonic() + stop_s
    status = "available"
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == "stopped":
            break
        time.sleep(2)
    if status != "stopped" and _budget_spent(ctx):
        raise TimeoutError(f"DB instance {inst_id} stopped: the run budget ended first; not graded")
    assert status == "stopped", f"Instance did not stop within {stop_s:.0f}s, last: {status}"

    # Start
    rds.start_db_instance(DBInstanceIdentifier=inst_id)
    _wait_available(rds, inst_id, timeout_s=_budget_s(ctx, 900), ctx=ctx)

    # Delete
    resp = rds.delete_db_instance(
        DBInstanceIdentifier=inst_id,
        SkipFinalSnapshot=True,
        DeleteAutomatedBackups=True,
    )
    assert resp["DBInstance"]["DBInstanceIdentifier"] == inst_id
    assert resp["DBInstance"]["DBInstanceStatus"] == "deleting", resp["DBInstance"]["DBInstanceStatus"]
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
        assert resp["DBInstances"][0]["DBInstanceStatus"] == "deleting"
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == ERR_DB_INSTANCE_NOT_FOUND

    # Prove the deleted id is gone AND unusable: wait out the deletion, then confirm the read
    # and an independent mutation on the same id are rejected the same way.
    _wait_gone(rds, inst_id, timeout_s=_budget_s(ctx, 1800), ctx=ctx)
    code, message = _client_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id))
    assert code == ERR_DB_INSTANCE_NOT_FOUND, code
    assert message == f"DBInstance {inst_id} not found.", message

    code, message = _client_error(lambda: rds.start_db_instance(DBInstanceIdentifier=inst_id))
    assert code == ERR_DB_INSTANCE_NOT_FOUND, code
    assert message == f"DBInstance {inst_id} not found.", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
