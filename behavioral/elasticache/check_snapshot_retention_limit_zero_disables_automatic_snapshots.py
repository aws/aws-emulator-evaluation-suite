"""snapshot-retention-limit-zero-disables-automatic-snapshots."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-retention-limit-zero-disables-automatic-snapshots"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SnapshotRetentionLimit=0, set at CreateCacheCluster time, persists as 0 through an
    independent DescribeCacheClusters read, and a manual CreateSnapshot still completes with
    SnapshotSource="manual"."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-snapz-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        SnapshotRetentionLimit=0,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))
    cluster = _wait_cluster_status(ec, cluster_id, "available", timeout_s=900)
    assert cluster["SnapshotRetentionLimit"] == 0, (
        f"SnapshotRetentionLimit persisted as {cluster['SnapshotRetentionLimit']!r}, expected 0"
    )

    snapshot_name = ctx.unique_name("sim2real-manualsnap-")
    ec.create_snapshot(CacheClusterId=cluster_id, SnapshotName=snapshot_name)
    ctx.on_cleanup(lambda: ec.delete_snapshot(SnapshotName=snapshot_name))
    manual_snapshot = _wait_snapshot_status(ec, snapshot_name, "available", timeout_s=900)
    assert manual_snapshot["SnapshotSource"] == "manual", (
        f"manual CreateSnapshot returned SnapshotSource={manual_snapshot['SnapshotSource']!r}, expected 'manual'"
    )


def _wait_cluster_status(ec, cluster_id, target_status, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
        if clusters and clusters[0]["CacheClusterStatus"] == target_status:
            return clusters[0]
        time.sleep(interval_s)
    raise AssertionError(f"cache cluster {cluster_id} never reached status {target_status!r} within {timeout_s}s")


def _wait_snapshot_status(ec, snapshot_name, target_status, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        snaps = ec.describe_snapshots(SnapshotName=snapshot_name)["Snapshots"]
        if snaps and snaps[0]["SnapshotStatus"] == target_status:
            return snaps[0]
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_name} never reached status {target_status!r} within {timeout_s}s")


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
            # DeleteCacheSubnetGroup refuses a group a cluster still holds with CacheSubnetGroupInUse.
            ("CacheSubnetGroupInUse", "InvalidCacheSubnetGroupState"),
            ("CacheSubnetGroupNotFoundFault",),
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
