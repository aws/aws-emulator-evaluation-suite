"""copy-db-cluster-snapshot-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-db-cluster-snapshot-round-trip"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CopyDBClusterSnapshot creates an independent cluster snapshot describable via DescribeDBClusterSnapshots."""
    rds = ctx.client("rds")

    sng = _subnet_group(ctx)
    cluster_id = ctx.unique_name("sim2real-snapclu-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2RealBehav1!",
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))

    inst_id = ctx.unique_name("sim2real-snapcluinst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id, DBInstanceClass="db.t3.medium", Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c["Status"] == "available",
        timeout_s=1800, interval_s=30, desc="cluster available",
    )

    src_snap_id = ctx.unique_name("sim2real-cluspnap-src-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=src_snap_id, DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_snapshot(rds, src_snap_id))

    src_snap = _wait_until(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=src_snap_id)["DBClusterSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200, interval_s=20, desc="source cluster snapshot available",
    )

    copy_snap_id = ctx.unique_name("sim2real-cluspnap-copy-")
    rds.copy_db_cluster_snapshot(
        SourceDBClusterSnapshotIdentifier=src_snap_id, TargetDBClusterSnapshotIdentifier=copy_snap_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_snapshot(rds, copy_snap_id))

    copy_snap = _wait_until(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=copy_snap_id)["DBClusterSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200, interval_s=20, desc="copied cluster snapshot available",
    )

    assert copy_snap["DBClusterSnapshotIdentifier"] != src_snap["DBClusterSnapshotIdentifier"], (
        f"copy identifier {copy_snap['DBClusterSnapshotIdentifier']!r} collided with source "
        f"{src_snap['DBClusterSnapshotIdentifier']!r}"
    )
    assert copy_snap["DBClusterSnapshotArn"] != src_snap["DBClusterSnapshotArn"], (
        f"copy ARN {copy_snap['DBClusterSnapshotArn']!r} collided with source {src_snap['DBClusterSnapshotArn']!r}"
    )
    assert copy_snap["Engine"] == src_snap["Engine"] == "aurora-mysql", (
        f"expected both snapshots to report engine aurora-mysql, "
        f"got copy={copy_snap['Engine']!r} src={src_snap['Engine']!r}"
    )

    rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=src_snap_id)
    _wait_gone(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=src_snap_id),
        {"DBClusterSnapshotNotFoundFault"}, timeout_s=300, interval_s=10, desc="source cluster snapshot deleted",
    )
    still_there = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=copy_snap_id)["DBClusterSnapshots"][0]
    assert still_there["Status"] == "available", (
        f"expected copy {copy_snap_id!r} to remain available after source deletion, "
        f"got status={still_there['Status']!r}"
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


def _subnet_group(ctx, name_prefix="sim2real-sng-"):

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span enough AZs for a DB subnet group")
    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids[:3],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _delete_cluster_snapshot(rds, snap_id):
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterSnapshotNotFoundFault":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id),
        {"DBClusterSnapshotNotFoundFault"}, timeout_s=300, interval_s=10, desc=f"cluster snapshot {snap_id} deleted",
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


def _delete_cluster(rds, cluster_id):
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id),
        {"DBClusterNotFoundFault"}, timeout_s=1200, interval_s=20, desc=f"cluster {cluster_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
