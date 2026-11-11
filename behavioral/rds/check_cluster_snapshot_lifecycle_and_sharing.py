"""cluster-snapshot-lifecycle-and-sharing."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-snapshot-lifecycle-and-sharing"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"
_SHARE_ACCOUNT = "111122223333"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cluster snapshot: creating -> available, attribute sharing, copy, and deletion."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    _wait_cluster_status(ctx, cluster_id, {"available"})

    snapshot_id = ctx.unique_name("sim2real-behav-snap-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snapshot_id,
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_snapshot(rds, snapshot_id))
    snap = _wait_snapshot_status(ctx, snapshot_id, {"available"}, timeout_s=1200.0)
    assert snap["Status"] == "available", f"expected snapshot {snapshot_id} available, got {snap['Status']!r}"

    attrs = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=snapshot_id)
    attr_list = attrs["DBClusterSnapshotAttributesResult"]["DBClusterSnapshotAttributes"]
    restore_attr = next((a for a in attr_list if a["AttributeName"] == "restore"), None)
    assert restore_attr is not None and restore_attr["AttributeValues"] == [], "snapshot should start private"

    rds.modify_db_cluster_snapshot_attribute(
        DBClusterSnapshotIdentifier=snapshot_id,
        AttributeName="restore",
        ValuesToAdd=[_SHARE_ACCOUNT],
    )
    attrs = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=snapshot_id)
    attr_list = attrs["DBClusterSnapshotAttributesResult"]["DBClusterSnapshotAttributes"]
    restore_attr = next(a for a in attr_list if a["AttributeName"] == "restore")
    assert _SHARE_ACCOUNT in restore_attr["AttributeValues"], (
        f"expected {_SHARE_ACCOUNT} in shared accounts after add, got {restore_attr['AttributeValues']!r}"
    )

    rds.modify_db_cluster_snapshot_attribute(
        DBClusterSnapshotIdentifier=snapshot_id,
        AttributeName="restore",
        ValuesToRemove=[_SHARE_ACCOUNT],
    )
    attrs = rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=snapshot_id)
    attr_list = attrs["DBClusterSnapshotAttributesResult"]["DBClusterSnapshotAttributes"]
    restore_attr = next(a for a in attr_list if a["AttributeName"] == "restore")
    assert _SHARE_ACCOUNT not in restore_attr["AttributeValues"], (
        f"expected {_SHARE_ACCOUNT} removed from shared accounts, still present in {restore_attr['AttributeValues']!r}"
    )

    copy_id = ctx.unique_name("sim2real-behav-snapcp-")
    rds.copy_db_cluster_snapshot(
        SourceDBClusterSnapshotIdentifier=snapshot_id,
        TargetDBClusterSnapshotIdentifier=copy_id,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_snapshot(rds, copy_id))
    copy_snap = _wait_snapshot_status(ctx, copy_id, {"available"}, timeout_s=1200.0)
    assert copy_snap["DBClusterIdentifier"] == cluster_id, (
        f"expected copy attributed to source cluster {cluster_id!r}, got {copy_snap['DBClusterIdentifier']!r}"
    )

    rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=copy_id)
    _wait_snapshot_gone(ctx, copy_id)
    rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_id)
    _wait_snapshot_gone(ctx, snapshot_id)

    code, message = _error_detail(lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id))
    assert code == "DBClusterSnapshotNotFoundFault", f"expected DBClusterSnapshotNotFoundFault, got {code!r}"
    expected = f"DBClusterSnapshot not found: {snapshot_id}"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"


def _safe_delete_snapshot(rds, snapshot_id: str) -> None:
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterSnapshotNotFoundFault":
            raise


def _error_detail(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call succeeded; expected a rejection")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets to create a DB subnet group"
    return ids


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 900.0) -> None:
    """Delete the cluster and wait until it is gone, so the subnet group teardown after it
    does not race a cluster still in "deleting"."""
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except rds.exceptions.DBClusterNotFoundFault:
            return
        time.sleep(15)
    raise AssertionError(f"cluster {cluster_id} was not deleted within {timeout_s}s")


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_cluster_status(ctx, cluster_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_snapshot_status(ctx, snapshot_id: str, statuses: set[str], timeout_s: float = 900.0, interval_s: float = 15.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)["DBClusterSnapshots"][0]

    return _poll_until(probe, lambda s: s["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_snapshot_gone(ctx, snapshot_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterSnapshotNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_id} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
