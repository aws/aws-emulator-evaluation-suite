"""serverless-cache-snapshot-retention-window-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "serverless-cache-snapshot-retention-window-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SnapshotRetentionLimit round-trips via ModifyServerlessCache and DescribeServerlessCaches,
    a manual snapshot reports SnapshotType "manual", and it stays available once the limit drops
    to 0. No retention period elapses; only the limit's value and the snapshot's survival are read."""
    ec = ctx.client("elasticache")
    cache_name = ctx.unique_name("sim2real-slcsnap-")
    ec.create_serverless_cache(
        ServerlessCacheName=cache_name,
        Engine="redis",
        SnapshotRetentionLimit=1,
        DailySnapshotTime="05:00",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: ec.delete_serverless_cache(ServerlessCacheName=cache_name))
    _wait_serverless_status(ec, cache_name, "available", timeout_s=900)

    ec.modify_serverless_cache(ServerlessCacheName=cache_name, SnapshotRetentionLimit=5)
    modified = _wait_serverless_field(ec, cache_name, "SnapshotRetentionLimit", 5, timeout_s=300)
    assert modified["SnapshotRetentionLimit"] == 5, (
        f"SnapshotRetentionLimit round-tripped as {modified['SnapshotRetentionLimit']!r}, expected 5"
    )

    snapshot_name = ctx.unique_name("sim2real-slcmansnap-")
    ec.create_serverless_cache_snapshot(
        ServerlessCacheName=cache_name,
        ServerlessCacheSnapshotName=snapshot_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=snapshot_name)
    )
    manual_snap = _wait_serverless_snapshot_status(ec, snapshot_name, "available", timeout_s=900)
    assert manual_snap["SnapshotType"] == "manual", (
        f"manual CreateServerlessCacheSnapshot returned SnapshotType={manual_snap['SnapshotType']!r}, expected 'manual'"
    )

    # Lowering SnapshotRetentionLimit to 0 (disabling automatic backups entirely) must not
    # cascade-delete the pre-existing manual snapshot -- manual snapshots are documented as
    # exempt from retention-limit expiry. A naive "expire anything over the limit"
    # implementation would delete it here.
    ec.modify_serverless_cache(ServerlessCacheName=cache_name, SnapshotRetentionLimit=0)
    _wait_serverless_field(ec, cache_name, "SnapshotRetentionLimit", 0, timeout_s=300)

    still_there = _wait_serverless_snapshot_status(ec, snapshot_name, "available", timeout_s=120)
    assert still_there["SnapshotType"] == "manual", (
        f"manual snapshot {snapshot_name!r} lost its SnapshotType after SnapshotRetentionLimit "
        f"dropped to 0: {still_there['SnapshotType']!r}"
    )


def _wait_serverless_status(ec, cache_name, target_status, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        caches = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"]
        if caches and caches[0]["Status"] == target_status:
            return caches[0]
        time.sleep(interval_s)
    raise AssertionError(f"serverless cache {cache_name} never reached status {target_status!r} within {timeout_s}s")


def _wait_serverless_field(ec, cache_name, field, target_value, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        caches = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"]
        if caches and caches[0].get(field) == target_value and caches[0]["Status"] == "available":
            return caches[0]
        time.sleep(interval_s)
    raise AssertionError(f"serverless cache {cache_name} field {field} never became {target_value!r} within {timeout_s}s")


def _wait_serverless_snapshot_status(ec, snapshot_name, target_status, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        snaps = ec.describe_serverless_cache_snapshots(
            ServerlessCacheSnapshotName=snapshot_name
        )["ServerlessCacheSnapshots"]
        if snaps and snaps[0]["Status"] == target_status:
            return snaps[0]
        time.sleep(interval_s)
    raise AssertionError(f"serverless cache snapshot {snapshot_name} never reached status {target_status!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
