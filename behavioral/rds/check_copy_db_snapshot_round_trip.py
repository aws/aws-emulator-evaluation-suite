"""copy-db-snapshot-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-db-snapshot-round-trip"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDBSnapshot creates a new, independent snapshot resource that becomes available and describable."""
    rds = ctx.client("rds")

    sng = _subnet_group(ctx)
    inst_id = ctx.unique_name("sim2real-snapsrc-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2RealBehav1!",
        AllocatedStorage=20,
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=1800, interval_s=30, desc="instance available",
    )

    src_snap_id = ctx.unique_name("sim2real-snap-src-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=src_snap_id,
        DBInstanceIdentifier=inst_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, src_snap_id))

    src_snap = _wait_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=src_snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200, interval_s=20, desc="source snapshot available",
    )

    copy_snap_id = ctx.unique_name("sim2real-snap-copy-")
    rds.copy_db_snapshot(
        SourceDBSnapshotIdentifier=src_snap_id,
        TargetDBSnapshotIdentifier=copy_snap_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, copy_snap_id))

    copy_snap = _wait_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=copy_snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200, interval_s=20, desc="copied snapshot available",
    )

    assert copy_snap["DBSnapshotIdentifier"] != src_snap["DBSnapshotIdentifier"], (
        f"copy {copy_snap['DBSnapshotIdentifier']!r} must not share the source's identifier "
        f"{src_snap['DBSnapshotIdentifier']!r}"
    )
    assert copy_snap["DBSnapshotArn"] != src_snap["DBSnapshotArn"], (
        f"copy ARN {copy_snap['DBSnapshotArn']!r} must differ from source ARN "
        f"{src_snap['DBSnapshotArn']!r}"
    )
    assert copy_snap["Engine"] == src_snap["Engine"] == "mysql", (
        f"expected both snapshots to report Engine='mysql', got copy={copy_snap['Engine']!r} "
        f"src={src_snap['Engine']!r}"
    )
    assert copy_snap["AllocatedStorage"] == src_snap["AllocatedStorage"] == 20, (
        f"expected both snapshots to report AllocatedStorage=20, got "
        f"copy={copy_snap['AllocatedStorage']!r} src={src_snap['AllocatedStorage']!r}"
    )

    # Deleting the source must not remove the independent copy.
    rds.delete_db_snapshot(DBSnapshotIdentifier=src_snap_id)
    _wait_gone(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=src_snap_id),
        {"DBSnapshotNotFound"}, timeout_s=300, interval_s=10, desc="source snapshot deleted",
    )
    still_there = rds.describe_db_snapshots(DBSnapshotIdentifier=copy_snap_id)["DBSnapshots"][0]
    assert still_there["Status"] == "available", (
        f"copy {copy_snap_id!r} should remain 'available' after the source snapshot was "
        f"deleted, got status={still_there['Status']!r}"
    )


def _wait_until(probe, predicate, timeout_s, interval_s=20, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last}")
        time.sleep(interval_s)


def _wait_gone(probe, not_found_codes, timeout_s, interval_s=20, desc="deletion"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}")
        time.sleep(interval_s)


def _await_enis_clear(ec2, subnet_id, timeout_s=900, interval_s=15):
    """RDS can leave an ENI attached to a subnet for a while after the DB instance it served is
    reported deleted; this VPC is created fresh for this check alone, so any ENI still in one of
    its subnets is necessarily ours to wait out, not another run's resource."""
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


def _delete_subnet_retry(ec2, subnet_id, timeout_s=120, interval_s=15):
    _await_enis_clear(ec2, subnet_id)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_vpc_retry(ec2, vpc_id, timeout_s=120, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _default_vpc_subnets(ec2, count, *, ctx):
    """Adopt the run's shared network when it has enough AZ coverage — the common case, and
    cheaper than provisioning a throwaway VPC on every run. Returns None (never raises) so the
    caller can fall back, rather than failing an account that simply has no shared network."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < count:
        return None
    return list(by_az.values())[:count]


def _dedicated_vpc_subnets(ctx, ec2, count):
    """No usable default VPC (a freshly provisioned account may not have one) — provision a
    throwaway VPC + subnets for this check alone, cleaned up via ctx.on_cleanup."""
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    if len(azs) < count:
        raise AssertionError(f"region {ctx.region!r} has only {len(azs)} available AZ(s); need >= {count}")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.194.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_retry(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.194.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "true"}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_subnet_retry(ec2, sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _subnet_group(ctx, name_prefix="sim2real-sng-"):
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    subnet_ids = _default_vpc_subnets(ec2, count=2, ctx=ctx) or _dedicated_vpc_subnets(ctx, ec2, count=2)

    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _delete_snapshot(rds, snap_id):
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id),
        {"DBSnapshotNotFound"}, timeout_s=300, interval_s=10, desc=f"snapshot {snap_id} deleted",
    )


def _delete_instance(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id),
        {"DBInstanceNotFound"}, timeout_s=1200, interval_s=20, desc=f"instance {inst_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
