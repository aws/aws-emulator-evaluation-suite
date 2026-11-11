"""cluster-snapshot-restore."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-snapshot-restore"
GROUP = 'snapshots'
SERVICES = ['rds']

def _wait_cluster_available(rds, cluster_id, timeout_s=900) -> None:
    """Poll until a DB cluster reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
            "DBClusters"
        ][0]["Status"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB cluster {cluster_id} available not met within {timeout_s}s")

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBClusterSnapshot -> available; RestoreDBClusterFromSnapshot creates
    a new cluster whose admin user name can only have come from the snapshot.

    Slow: provisions a real Aurora cluster + snapshot + restore.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster(
        DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True))
    _wait_cluster_available(rds, cluster_id)

    snap_id = ctx.unique_name("sim2real-behav-clusnap-")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snap_id, DBClusterIdentifier=cluster_id
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snap_id))

    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        snap_status = rds.describe_db_cluster_snapshots(
            DBClusterSnapshotIdentifier=snap_id
        )["DBClusterSnapshots"][0]["Status"]
        if snap_status == "available":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"cluster snapshot {snap_id} available not met in time")

    restored_id = ctx.unique_name("sim2real-behav-clu-restored-")
    rds.restore_db_cluster_from_snapshot(
        DBClusterIdentifier=restored_id,
        SnapshotIdentifier=snap_id,
        Engine="aurora-mysql",
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster(
        DBClusterIdentifier=restored_id, SkipFinalSnapshot=True))
    _wait_cluster_available(rds, restored_id)

    restored = rds.describe_db_clusters(DBClusterIdentifier=restored_id)["DBClusters"][0]
    assert restored["Engine"] == "aurora-mysql", (
        f"expected engine aurora-mysql, got {restored['Engine']!r}"
    )
    # RestoreDBClusterFromSnapshot accepts no admin user name parameter, so
    # this value can only have flowed from the snapshot, not from the restore call.
    assert restored["MasterUsername"] == "sim2real", (
        f"expected master username inherited from snapshot ('sim2real'), "
        f"got {restored['MasterUsername']!r}"
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
