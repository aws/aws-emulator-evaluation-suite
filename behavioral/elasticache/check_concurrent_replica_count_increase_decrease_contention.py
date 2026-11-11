"""concurrent-replica-count-increase-decrease-contention."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-replica-count-increase-decrease-contention"
GROUP = "concurrency"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Simultaneous IncreaseReplicaCount and DecreaseReplicaCount on one replication group are
    serialized: exactly one wins, the other is rejected for an in-progress state, and the final
    replica count is consistent."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-repliccontend-")
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="concurrent replica count contention test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=3,
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        CacheSubnetGroupName=_network_cache_subnet_group(ctx, ec),
    )
    ctx.on_cleanup(lambda: _retry_while_held(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id), "InvalidReplicationGroupState", timeout_s=900.0))
    _wait_rg_status(ec, rg_id, "available", ctx=ctx, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0)

    # Both calls leave the barrier together, so the second lands inside the first's modifying
    # window regardless of how late the pool schedules its thread.
    start = threading.Barrier(2)

    def _increase():
        start.wait(timeout=30)
        try:
            ec.increase_replica_count(ReplicationGroupId=rg_id, NewReplicaCount=3, ApplyImmediately=True)
            return ("ok", "increase", 3, None, None)
        except ClientError as e:
            return ("error", "increase", 3, e.response["Error"]["Code"], e.response["Error"]["Message"])

    def _decrease():
        start.wait(timeout=30)
        try:
            ec.decrease_replica_count(ReplicationGroupId=rg_id, NewReplicaCount=1, ApplyImmediately=True)
            return ("ok", "decrease", 1, None, None)
        except ClientError as e:
            return ("error", "decrease", 1, e.response["Error"]["Code"], e.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_increase), pool.submit(_decrease)]
        results = [f.result() for f in futures]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winning replica-count call, got {len(successes)}: {results}"
    assert len(failures) == 1, f"expected exactly one rejected replica-count call, got {len(failures)}: {results}"
    assert failures[0][3] == "InvalidReplicationGroupState", (
        f"loser call failed with {failures[0][3]!r}, expected 'InvalidReplicationGroupState'"
    )
    if failures[0][1] == "increase":
        message = failures[0][4]
        assert message == "Replication group must be in available state to modify.", (
            f"unexpected IncreaseReplicaCount refusal message {message!r}"
        )

    winning_replica_count = successes[0][2]
    final = _wait_rg_status(ec, rg_id, "available", ctx=ctx, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0)
    final_replica_count = len(final["NodeGroups"][0]["NodeGroupMembers"]) - 1
    assert final_replica_count == winning_replica_count, (
        f"final replica count is {final_replica_count}, expected the winning call's target "
        f"{winning_replica_count} (not a race-corrupted value); results={results}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_rg_status(ec, rg_id, target_status, timeout_s=1200.0, interval_s=15.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups and groups[0]["Status"] == target_status:
            return groups[0]
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"replication group {rg_id} reaching status {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(f"replication group {rg_id} never reached status {target_status!r} within {timeout_s}s")


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
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.
    The 1500 s window fits within this suite's 1800 s teardown budget."""
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


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
