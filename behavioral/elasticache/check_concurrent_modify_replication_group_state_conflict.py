"""concurrent-modify-replication-group-state-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-modify-replication-group-state-conflict"
GROUP = "concurrency"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent ModifyReplicationGroup calls setting different SnapshotRetentionLimit values
    serialize: at least one succeeds, any loser fails with InvalidReplicationGroupState, and the
    final limit is one of the two requested values (no lost or corrupted update)."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-race-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real concurrent modify state-conflict check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        SnapshotRetentionLimit=0,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, rg_id))
    rg = _wait_for_status(ec, rg_id, {"available"}, timeout_s=1200)
    snapshotting_cluster_id = rg["MemberClusters"][0]

    def _call(limit: int) -> dict:
        from botocore.exceptions import ClientError

        try:
            ec.modify_replication_group(
                ReplicationGroupId=rg_id,
                SnapshotRetentionLimit=limit,
                SnapshottingClusterId=snapshotting_cluster_id,
                ApplyImmediately=True,
            )
            return {"ok": True, "code": None, "limit": limit}
        except ClientError as exc:
            return {
                "ok": False,
                "code": exc.response["Error"]["Code"],
                "message": exc.response["Error"].get("Message"),
                "limit": limit,
            }

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_call, 1), pool.submit(_call, 2)]
        results = [f.result() for f in futures]

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]

    assert len(successes) >= 1, f"neither concurrent modify call succeeded: {results}"
    for r in failures:
        assert r["code"] == "InvalidReplicationGroupState", (
            f"unexpected error code for a racing modify call: {r['code']!r} (full: {results})"
        )
        assert r["message"] == "Replication group must be in available state to modify.", (
            f"unexpected message for a racing modify call: {r['message']!r} (full: {results})"
        )

    _wait_for_status(ec, rg_id, {"available"}, timeout_s=300)
    final_limit = _describe(ec, rg_id)["SnapshotRetentionLimit"]
    assert final_limit in (1, 2), (
        f"final SnapshotRetentionLimit {final_limit!r} matches neither racer's requested "
        "value -- a lost or corrupted update"
    )


def _describe(ec: Any, rg_id: str) -> dict:
    return ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]


def _wait_for_status(ec: Any, rg_id: str, targets: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        rg = _describe(ec, rg_id)
        last = rg["Status"]
        if last in targets:
            return rg
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached {targets}; last={last}")


def _delete_replication_group(ec: Any, rg_id: str) -> None:
    """Delete rg_id and wait until it is gone; a group still creating is retried."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900
    while True:
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code != "InvalidReplicationGroupState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} was not deleted within 900 s")


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
