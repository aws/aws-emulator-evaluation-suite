"""snapshot-lifecycle-from-cluster."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, actual = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code} ({actual!r})"
    assert actual == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {actual!r}"
    return code

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _wait_deleted(fn, list_key, id_field, id_value, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _wait_cluster_status(ec, cluster_id, status, timeout_s=1800, interval_s=15):
    return _wait_status(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterStatus", status, timeout_s, interval_s)

def _wait_cluster_deleted(ec, cluster_id, timeout_s=1200, interval_s=15):
    return _wait_deleted(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, timeout_s, interval_s)

def _describe_snapshot(ec, name):
    return _describe_one(ec.describe_snapshots, "Snapshots", "SnapshotName", name)

def _wait_snapshot_status(ec, name, status, timeout_s=1800, interval_s=15):
    return _wait_status(ec.describe_snapshots, "Snapshots", "SnapshotName", name, "SnapshotStatus", status, timeout_s, interval_s)

def _wait_snapshot_deleted(ec, name, timeout_s=1200, interval_s=10):
    return _wait_deleted(ec.describe_snapshots, "Snapshots", "SnapshotName", name, timeout_s, interval_s)

def _delete_tolerant(fn):
    """Teardown delete that treats an already-deleted resource as done."""
    try:
        fn()
    except ClientError as e:
        if "NotFound" not in (e.response.get("Error", {}).get("Code") or ""):
            raise

CHECK = "snapshot-lifecycle-from-cluster"
GROUP = 'snapshot'
SERVICES = ['elasticache']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A manual snapshot of a cluster becomes available naming its cluster, source manual and engine redis;
    CreateSnapshot and CopySnapshot to its name are refused with SnapshotAlreadyExists and exact messages, leaving
    one snapshot, and once deleted a second delete fails with SnapshotNotFound and its exact message."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-behav-ecc-snap-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        SnapshotRetentionLimit=0,
        Tags=_MANAGED_TAGS,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_tolerant(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id)))
    _wait_cluster_status(ec, cluster_id, "available", timeout_s=1500)

    snapshot_name = ctx.unique_name("sim2real-behav-ecs-snap-")
    created = ec.create_snapshot(
        CacheClusterId=cluster_id, SnapshotName=snapshot_name, Tags=_MANAGED_TAGS,
    )["Snapshot"]
    ctx.on_cleanup(lambda: _delete_tolerant(lambda: ec.delete_snapshot(SnapshotName=snapshot_name)))
    assert created["SnapshotStatus"] in ("creating", "available"), (
        f"expected creating/available right after CreateSnapshot, got {created['SnapshotStatus']!r}"
    )
    assert created["SnapshotSource"] == "manual", f"expected SnapshotSource manual, got {created!r}"

    snapshot = _wait_snapshot_status(ec, snapshot_name, "available", timeout_s=900)
    assert snapshot is not None, f"expected snapshot {snapshot_name!r} to become available, got nothing"
    assert snapshot["CacheClusterId"] == cluster_id, (
        f"expected CacheClusterId {cluster_id!r}, got {snapshot['CacheClusterId']!r}"
    )
    assert snapshot["SnapshotSource"] == "manual", (
        f"expected SnapshotSource manual, got {snapshot['SnapshotSource']!r}"
    )
    assert snapshot["Engine"] == "redis", f"expected Engine redis, got {snapshot['Engine']!r}"
    assert snapshot.get("NodeSnapshots"), f"expected a non-empty NodeSnapshots, got {snapshot!r}"

    # The name is now taken.
    _assert_error(lambda: ec.create_snapshot(
        CacheClusterId=cluster_id, SnapshotName=snapshot_name,
    ), ("SnapshotAlreadyExistsFault", "Snapshot with specified name already exists."))

    # CopySnapshot cannot overwrite an existing target name either.
    _assert_error(lambda: ec.copy_snapshot(
        SourceSnapshotName=snapshot_name, TargetSnapshotName=snapshot_name,
    ), ("SnapshotAlreadyExistsFault", "A destination snapshot with the specified name already exists"))

    # Effect absent: neither rejected call mutated or duplicated the original snapshot.
    unaffected = ec.describe_snapshots(SnapshotName=snapshot_name)["Snapshots"]
    assert len(unaffected) == 1, (
        f"expected exactly 1 snapshot named {snapshot_name!r} after the rejected duplicates, "
        f"got {len(unaffected)}: {unaffected!r}"
    )
    assert unaffected[0]["SnapshotStatus"] == "available", (
        f"expected the original snapshot to remain available, got {unaffected[0]['SnapshotStatus']!r}"
    )

    ec.delete_snapshot(SnapshotName=snapshot_name)
    _wait_snapshot_deleted(ec, snapshot_name, timeout_s=600)
    assert _describe_snapshot(ec, snapshot_name) is None, (
        f"expected snapshot {snapshot_name!r} to be gone after DeleteSnapshot"
    )

    # A mutation on the now-dead snapshot id must also fail, not silently no-op.
    _assert_error(
        lambda: ec.delete_snapshot(SnapshotName=snapshot_name),
        ("SnapshotNotFoundFault",
        f"Snapshot with name {snapshot_name} not found"),
    )

    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _wait_cluster_deleted(ec, cluster_id, timeout_s=1200)
    assert _describe_one(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id) is None, (
        f"expected cluster {cluster_id!r} to be gone after DeleteCacheCluster"
    )


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
