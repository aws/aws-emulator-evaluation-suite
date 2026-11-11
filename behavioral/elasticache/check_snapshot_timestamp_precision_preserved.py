"""snapshot-timestamp-precision-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A snapshot's per-node SnapshotCreateTime/CacheNodeCreateTime timestamps stay
    byte-for-byte stable across repeated DescribeSnapshots calls (not regenerated per call)."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-snaprts-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))
    _wait_cluster_status(ec, cluster_id, "available", timeout_s=_budget_s(ctx, 900), ctx=ctx)

    snapshot_name = ctx.unique_name("sim2real-snap-")
    ec.create_snapshot(CacheClusterId=cluster_id, SnapshotName=snapshot_name)
    ctx.on_cleanup(lambda: ec.delete_snapshot(SnapshotName=snapshot_name))
    first = _wait_snapshot_status(ec, snapshot_name, "available", timeout_s=_budget_s(ctx, 900),
                                  ctx=ctx)
    first_node = first["NodeSnapshots"][0]

    # Hold for longer than the timestamps' own (second-level) precision: two reads issued
    # back-to-back could coincidentally land in the same second even if the target wrongly
    # regenerates the timestamp from the live clock on every DescribeSnapshots call.
    _hold(1.5)
    second = ec.describe_snapshots(SnapshotName=snapshot_name)["Snapshots"][0]
    second_node = second["NodeSnapshots"][0]

    _hold(1.5)
    third = ec.describe_snapshots(SnapshotName=snapshot_name)["Snapshots"][0]
    third_node = third["NodeSnapshots"][0]

    assert first["CacheClusterCreateTime"] == second["CacheClusterCreateTime"] == third["CacheClusterCreateTime"], (
        "Snapshot.CacheClusterCreateTime drifted across repeated DescribeSnapshots calls: "
        f"{first['CacheClusterCreateTime']!r} / {second['CacheClusterCreateTime']!r} / {third['CacheClusterCreateTime']!r}"
    )
    assert (
        first_node["SnapshotCreateTime"] == second_node["SnapshotCreateTime"] == third_node["SnapshotCreateTime"]
    ), (
        "NodeSnapshot.SnapshotCreateTime drifted across repeated DescribeSnapshots calls: "
        f"{first_node['SnapshotCreateTime']!r} / {second_node['SnapshotCreateTime']!r} / {third_node['SnapshotCreateTime']!r}"
    )


def _hold(duration_s: float) -> None:
    """Bounded wait for `duration_s` of wall-clock time to pass (a deadline, not a bare sleep)."""
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_status(ec, cluster_id, target_status, timeout_s=900.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
        if clusters and clusters[0]["CacheClusterStatus"] == target_status:
            return clusters[0]
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cache cluster {cluster_id} reaching {target_status!r}: the run budget "
                           f"ended first; not graded")
    raise AssertionError(f"cache cluster {cluster_id} never reached status {target_status!r} within {timeout_s}s")


def _wait_snapshot_status(ec, snapshot_name, target_status, timeout_s=900.0, interval_s=2.0,
                          ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        snaps = ec.describe_snapshots(SnapshotName=snapshot_name)["Snapshots"]
        if snaps and snaps[0]["SnapshotStatus"] == target_status:
            return snaps[0]
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"snapshot {snapshot_name} reaching {target_status!r}: the run budget "
                           f"ended first; not graded")
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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
