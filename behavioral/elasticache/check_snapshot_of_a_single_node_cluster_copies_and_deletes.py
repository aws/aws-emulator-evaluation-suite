"""snapshot-of-a-single-node-cluster-copies-and-deletes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-of-a-single-node-cluster-copies-and-deletes"
GROUP = 'snapshot'
SERVICES = ['elasticache']

_MANAGED_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code") or ""


def _describe_one(fn, list_key, id_field, id_value, not_found_marker, **extra):
    """describe wrapper: return the single item, None on a NotFound fault / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        if not_found_marker in _code(e):
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None


def _poll(probe, predicate, timeout_s, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _wait_cluster_available(ec, cluster_id, timeout_s=1500):
    return _poll(
        lambda: _describe_one(
            ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterNotFound"
        ),
        lambda item: item is not None and item.get("CacheClusterStatus") == "available",
        timeout_s,
    )


def _wait_cluster_deleted(ec, cluster_id, timeout_s=1200):
    return _poll(
        lambda: _describe_one(
            ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterNotFound"
        ),
        lambda item: item is None,
        timeout_s,
    )


def _describe_snapshot(ec, name):
    return _describe_one(ec.describe_snapshots, "Snapshots", "SnapshotName", name, "SnapshotNotFound")


def _wait_snapshot_available(ec, name, timeout_s=900):
    return _poll(
        lambda: _describe_snapshot(ec, name),
        lambda item: item is not None and item.get("SnapshotStatus") == "available",
        timeout_s,
    )


def _wait_snapshot_deleted(ec, name, timeout_s=600):
    return _poll(lambda: _describe_snapshot(ec, name), lambda item: item is None, timeout_s)


def _ignore_not_found(fn, marker):
    try:
        fn()
    except ClientError as e:
        if marker not in _code(e):
            raise


def _cleanup_snapshot(ec, name):
    """Teardown: a snapshot mid creating/copying rejects DeleteSnapshot, so wait for it to
    resolve (or vanish) before deleting."""
    try:
        _poll(
            lambda: _describe_snapshot(ec, name),
            lambda item: item is None or item.get("SnapshotStatus") not in ("creating", "copying"),
            900,
        )
    except AssertionError:
        pass
    _ignore_not_found(lambda: ec.delete_snapshot(SnapshotName=name), "SnapshotNotFound")


def _cleanup_cluster(ec, cluster_id):
    """Teardown: a cluster mid snapshotting rejects DeleteCacheCluster, so wait for it to
    resolve (or vanish) before deleting."""
    try:
        _poll(
            lambda: _describe_one(
                ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterNotFound"
            ),
            lambda item: item is None or item.get("CacheClusterStatus") not in ("creating", "snapshotting", "modifying"),
            1500,
        )
    except AssertionError:
        pass
    _ignore_not_found(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id), "CacheClusterNotFound")


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSnapshot of a single-node Redis cluster becomes available with exactly one
    NodeSnapshot; CopySnapshot produces an independent second snapshot that survives deleting
    the first; then both delete clean."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-behav-ecc-snapcp-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t4g.micro",
        NumCacheNodes=1,
        SnapshotRetentionLimit=0,
        Tags=_MANAGED_TAGS,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _cleanup_cluster(ec, cluster_id))
    _wait_cluster_available(ec, cluster_id, timeout_s=1500)

    source_name = ctx.unique_name("sim2real-behav-ecs-src-")
    ec.create_snapshot(CacheClusterId=cluster_id, SnapshotName=source_name, Tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: _cleanup_snapshot(ec, source_name))

    source = _wait_snapshot_available(ec, source_name, timeout_s=900)
    assert source is not None, f"expected snapshot {source_name!r} to become available"
    assert source["CacheClusterId"] == cluster_id, (
        f"expected CacheClusterId {cluster_id!r}, got {source['CacheClusterId']!r}"
    )
    source_nodes = source.get("NodeSnapshots", [])
    assert len(source_nodes) == 1, (
        f"expected exactly 1 NodeSnapshot for a single-node cluster, got {len(source_nodes)}: {source_nodes!r}"
    )

    target_name = ctx.unique_name("sim2real-behav-ecs-cpy-")
    copied = ec.copy_snapshot(SourceSnapshotName=source_name, TargetSnapshotName=target_name)["Snapshot"]
    ctx.on_cleanup(lambda: _cleanup_snapshot(ec, target_name))
    assert copied["SnapshotStatus"] in ("creating", "copying", "available"), (
        f"expected creating/copying/available right after CopySnapshot, got {copied['SnapshotStatus']!r}"
    )

    target = _wait_snapshot_available(ec, target_name, timeout_s=900)
    assert target is not None, f"expected copy {target_name!r} to become available"
    assert target["CacheClusterId"] == cluster_id, (
        f"expected the copy to record the original source cluster {cluster_id!r}, got {target['CacheClusterId']!r}"
    )
    target_nodes = target.get("NodeSnapshots", [])
    assert len(target_nodes) == 1, (
        f"expected the copy to carry 1 NodeSnapshot too, got {len(target_nodes)}: {target_nodes!r}"
    )

    both = {n for n in (source_name, target_name) if _describe_snapshot(ec, n) is not None}
    assert both == {source_name, target_name}, f"expected both snapshots to coexist, found {both!r}"

    ec.delete_snapshot(SnapshotName=source_name)
    _wait_snapshot_deleted(ec, source_name, timeout_s=600)
    assert _describe_snapshot(ec, source_name) is None, f"expected {source_name!r} to be gone after delete"

    survivor = _describe_snapshot(ec, target_name)
    assert survivor is not None, f"expected the copy {target_name!r} to survive deleting its source"
    assert survivor["SnapshotStatus"] == "available", (
        f"expected the surviving copy to remain available, got {survivor['SnapshotStatus']!r}"
    )

    ec.delete_snapshot(SnapshotName=target_name)
    _wait_snapshot_deleted(ec, target_name, timeout_s=600)
    assert _describe_snapshot(ec, target_name) is None, f"expected {target_name!r} to be gone after delete"

    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _wait_cluster_deleted(ec, cluster_id, timeout_s=1200)
    assert _describe_one(
        ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterNotFound"
    ) is None, f"expected cluster {cluster_id!r} to be gone after delete"


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
