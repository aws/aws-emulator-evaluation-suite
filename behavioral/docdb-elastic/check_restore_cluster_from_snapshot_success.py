"""restore-cluster-from-snapshot-success."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "restore-cluster-from-snapshot-success"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreClusterFromSnapshot creates a brand-new cluster (none) -> CREATING ->
    ACTIVE whose shard topology matches the snapshot's source cluster, and which gets
    its own distinct clusterArn/clusterEndpoint independent of the original cluster."""
    client = ctx.client("docdb-elastic")
    source_name = ctx.unique_name("sim2real-elastic-restsrc-")

    source_arn = client.create_cluster(
        clusterName=source_name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=2,
        tags={"sim2real-check": CHECK},
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(client, source_arn))
    source_active = _wait_for_cluster_status(client, source_arn, {"ACTIVE"})

    snapshot_name = ctx.unique_name("sim2real-elastic-restore-snap-")
    snapshot_arn = client.create_cluster_snapshot(
        clusterArn=source_arn, snapshotName=snapshot_name, tags={"sim2real-check": CHECK}
    )["snapshot"]["snapshotArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_snapshot(client, snapshot_arn))
    _wait_for_snapshot_status(client, snapshot_arn, {"ACTIVE"})

    restored_name = ctx.unique_name("sim2real-elastic-restored-")
    restored_arn = client.restore_cluster_from_snapshot(
        clusterName=restored_name, snapshotArn=snapshot_arn, tags={"sim2real-check": CHECK}
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(client, restored_arn))
    assert restored_arn != source_arn, (
        f"restored cluster arn {restored_arn!r} must differ from source arn {source_arn!r}"
    )

    restored_active = _wait_for_cluster_status(client, restored_arn, {"ACTIVE"})
    assert restored_active["clusterName"] == restored_name.lower(), (
        f"expected restored clusterName {restored_name.lower()!r}, "
        f"got {restored_active['clusterName']!r}"
    )
    assert restored_active["clusterEndpoint"] != source_active["clusterEndpoint"], (
        "restored cluster must get its own endpoint independent of the source, "
        f"got the same endpoint as source: {source_active['clusterEndpoint']!r}"
    )
    assert restored_active["shardCapacity"] == source_active["shardCapacity"], (
        f"expected restored shardCapacity to match source cluster's own reported "
        f"{source_active['shardCapacity']!r}, got {restored_active['shardCapacity']!r}"
    )
    assert restored_active["shardCount"] == source_active["shardCount"], (
        f"expected restored shardCount to match source cluster's own reported "
        f"{source_active['shardCount']!r}, got {restored_active['shardCount']!r}"
    )
    assert len(restored_active["shards"]) == len(source_active["shards"]), (
        f"expected restored shard topology ({len(source_active['shards'])} shards, "
        f"matching source) but got {len(restored_active['shards'])}"
    )
    assert restored_active["adminUserName"] == _ADMIN_USER, (
        f"expected restored cluster to inherit adminUserName {_ADMIN_USER!r} from the "
        f"snapshot's source cluster, got {restored_active.get('adminUserName')!r}"
    )


def _wait_for_cluster_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


def _wait_for_snapshot_status(client, snapshot_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        snapshot = client.get_cluster_snapshot(snapshotArn=snapshot_arn)["snapshot"]
        last_status = snapshot["status"]
        if last_status in target_statuses:
            return snapshot
        time.sleep(interval_s)
    raise AssertionError(f"snapshot never reached {target_statuses}, last status={last_status}")


def _best_effort_delete_cluster(client, cluster_arn):
    try:
        client.delete_cluster(clusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_snapshot(client, snapshot_arn):
    try:
        client.delete_cluster_snapshot(snapshotArn=snapshot_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
