"""snapshot-retention-limit-auto-expiry."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-retention-limit-auto-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SnapshotRetentionLimit round-trips through create and ModifyCacheCluster (1, 3, then 0),
    and lowering it to 0 leaves a pre-existing manual snapshot available: manual snapshots are
    exempt from retention-limit expiry."""
    # Automatic snapshots are daily with no way to force one, so their age-out is not observed.
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-snaplimit-")
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        SnapshotRetentionLimit=1,
        CacheSubnetGroupName=_network_cache_subnet_group(ctx, ec),
    )
    ctx.on_cleanup(lambda: _delete_cluster(ec, cluster_id))
    _wait_for_cluster_status(ec, cluster_id, {"available"}, timeout_s=900)

    initial = _describe_cluster(ec, cluster_id)
    assert initial["SnapshotRetentionLimit"] == 1, (
        f"SnapshotRetentionLimit not persisted at creation: {initial['SnapshotRetentionLimit']!r}"
    )

    ec.modify_cache_cluster(
        CacheClusterId=cluster_id, SnapshotRetentionLimit=3, ApplyImmediately=True
    )
    _wait_for_field(ec, cluster_id, "SnapshotRetentionLimit", 3, timeout_s=180)

    snapshot_name = ctx.unique_name("sim2real-snaplimit-snap-")
    ec.create_snapshot(SnapshotName=snapshot_name, CacheClusterId=cluster_id)
    ctx.on_cleanup(lambda: _delete_snapshot(ec, snapshot_name))
    snap = _wait_for_snapshot_status(ec, snapshot_name, {"available"}, timeout_s=600)
    assert snap["SnapshotSource"] == "manual", (
        f"CreateSnapshot did not produce a manual snapshot: SnapshotSource={snap['SnapshotSource']!r}"
    )

    # 0 disables automatic backups; a manual snapshot must not be expired by it.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id, SnapshotRetentionLimit=0, ApplyImmediately=True
    )
    _wait_for_field(ec, cluster_id, "SnapshotRetentionLimit", 0, timeout_s=180)

    still_there = _wait_for_snapshot_status(ec, snapshot_name, {"available"}, timeout_s=120)
    assert still_there["SnapshotSource"] == "manual", (
        f"expected SnapshotSource still 'manual' after retention-limit change, "
        f"got {still_there['SnapshotSource']!r}"
    )
    assert still_there["SnapshotStatus"] == "available", (
        "manual snapshot was removed after SnapshotRetentionLimit was lowered to 0"
    )


def _describe_cluster(ec: Any, cluster_id: str) -> dict:
    return ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]


def _wait_for_cluster_status(ec: Any, cluster_id: str, targets: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_cluster(ec, cluster_id)
        if last["CacheClusterStatus"] in targets:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets}; last={last}")


def _wait_for_field(ec: Any, cluster_id: str, field: str, value: Any, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_cluster(ec, cluster_id).get(field)
        if last == value:
            return
        time.sleep(2)
    raise AssertionError(f"{field} never became {value!r}; last observed {last!r}")


def _wait_for_snapshot_status(ec: Any, snapshot_name: str, targets: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ec.describe_snapshots(SnapshotName=snapshot_name)
        snapshots = resp.get("Snapshots", [])
        if snapshots:
            last = snapshots[0]
            if last["SnapshotStatus"] in targets:
                return last
        time.sleep(2)
    raise AssertionError(f"snapshot {snapshot_name} never reached {targets}; last={last}")


def _delete_snapshot(ec: Any, snapshot_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ec.delete_snapshot(SnapshotName=snapshot_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SnapshotNotFoundFault":
            raise


def _delete_cluster(ec: Any, cluster_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "CacheClusterNotFound":
            raise
        return
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("CacheClusterNotFound", "CacheClusterNotFoundFault"):
                return
            raise
        time.sleep(15)


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
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
