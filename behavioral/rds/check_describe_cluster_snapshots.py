"""describe-cluster-snapshots."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-cluster-snapshots"
GROUP = 'snapshots'
SERVICES = ['rds']


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _cluster(rds, cid):
    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=cid).get("DBClusters", [])
        return clusters[0] if clusters else None
    except ClientError:
        return None


def _manual_cluster_snapshot(rds, snap_id):
    resp = rds.describe_db_cluster_snapshots(
        DBClusterSnapshotIdentifier=snap_id, SnapshotType="manual"
    )
    snaps = resp.get("DBClusterSnapshots", [])
    return snaps[0] if snaps else None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusterSnapshots: a real manual cluster snapshot becomes describable by identifier
    and by SnapshotType=manual filter. Error boundary: filtering by an unknown
    DBClusterSnapshotIdentifier rejects with DBClusterSnapshotNotFoundFault.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword=_make_password(),
        BackupRetentionPeriod=1,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _poll_until(
        lambda: _cluster(rds, cluster_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"cluster {cluster_id} available",
    )

    snap_id = ctx.unique_name("sim2real-behav-csnap-")
    rds.create_db_cluster_snapshot(
        DBClusterIdentifier=cluster_id, DBClusterSnapshotIdentifier=snap_id
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    )
    snap = _manual_cluster_snapshot(rds, snap_id)
    snap = _poll_until(
        lambda: _manual_cluster_snapshot(rds, snap_id),
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"cluster snapshot {snap_id} available",
    )
    assert snap is not None, (
        f"expected snapshot {snap_id} to be describable via SnapshotType=manual filter, got None"
    )
    assert snap["DBClusterSnapshotIdentifier"] == snap_id, (
        f"expected DBClusterSnapshotIdentifier={snap_id!r}, got {snap.get('DBClusterSnapshotIdentifier')!r}"
    )
    assert snap["DBClusterIdentifier"] == cluster_id, (
        f"expected DBClusterIdentifier={cluster_id!r}, got {snap.get('DBClusterIdentifier')!r}"
    )
    assert snap["SnapshotType"] == "manual", (
        f"expected SnapshotType='manual', got {snap.get('SnapshotType')!r}"
    )
    assert snap["Status"] == "available", (
        f"expected Status='available', got {snap.get('Status')!r}"
    )

    bogus_snap = ctx.unique_name("sim2real-behav-csnap-missing-")
    err = _rejection(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=bogus_snap)
    )
    assert err.get("Code") == "DBClusterSnapshotNotFoundFault", f"unexpected error: {err}"
    assert err.get("Message") == f"DBClusterSnapshot not found: {bogus_snap}", (
        f"unexpected DBClusterSnapshotNotFoundFault message: {err}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
