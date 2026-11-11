"""concurrent-shard-config-modification-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-shard-config-modification-conflict"
GROUP = "concurrency"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two concurrent ModifyReplicationGroupShardConfiguration calls on one cluster-mode group,
    exactly one succeeds and the other is rejected with InvalidReplicationGroupState; the group
    settles on the winning shard count."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-shardrace-")
    # Real ElastiCache rejects a cluster-mode-enabled (NumNodeGroups>1) CreateReplicationGroup
    # with AutomaticFailoverEnabled=False/ReplicasPerNodeGroup=0 ("Redis with cluster mode
    # enabled cannot be created with auto failover turned off") and with a T-family node type
    # ("... cannot be created with cache node type cache.t3.micro") -- cluster mode requires a
    # replica for failover to target and a node type with headroom for the cluster bus.
    teardown = {}
    subnet_group = _network_cache_subnet_group(ctx, ec, teardown)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="concurrent shard reconfiguration conflict test",
        Engine="redis",
        CacheNodeType="cache.m5.large",
        NumNodeGroups=2,
        ReplicasPerNodeGroup=1,
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, rg_id, teardown))
    _wait_rg_status(ec, rg_id, "available", ctx=ctx, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0)

    # Both calls leave the barrier together, so the second lands inside the first's modifying
    # window regardless of how late the pool schedules its thread.
    start = threading.Barrier(2)

    def _reshard(target_count):
        start.wait(timeout=30)
        try:
            ec.modify_replication_group_shard_configuration(
                ReplicationGroupId=rg_id,
                NodeGroupCount=target_count,
                ApplyImmediately=True,
            )
            return ("ok", target_count, None, None)
        except ClientError as e:
            return ("error", target_count, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_reshard, 3), pool.submit(_reshard, 4)]
        results = [f.result() for f in futures]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winning reshard call, got {len(successes)}: {results}"
    assert len(failures) == 1, f"expected exactly one rejected reshard call, got {len(failures)}: {results}"
    assert failures[0][2] == "InvalidReplicationGroupState", (
        f"loser reshard call failed with {failures[0][2]!r}, expected 'InvalidReplicationGroupState'"
    )
    assert failures[0][3] == "Could not reshard replication group. Please try again later.", (
        f"loser reshard call failed with message {failures[0][3]!r}"
    )

    winning_count = successes[0][1]
    final = _wait_rg_status(ec, rg_id, "available", ctx=ctx, timeout_s=_budget_s(ctx, 1200.0), interval_s=2.0)
    assert len(final["NodeGroups"]) == winning_count, (
        f"final NodeGroup count is {len(final['NodeGroups'])}, expected the winning call's target "
        f"{winning_count} (not a corrupted mix of {results})"
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


def _network_cache_subnet_group(ctx, client, teardown) -> str:
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
            _deadline(teardown),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, deadline):
    """Delete a subnet group, retrying every 2 s to ``deadline`` while a resource that is being deleted
    still uses it."""
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
        time.sleep(2)


# Inside the 1800 s elasticache cleanup budget, one deadline shared by every teardown of a run.
_TEARDOWN_S = 1680.0


def _deadline(shared):
    """The run's teardown deadline, fixed by the first teardown that runs."""
    return shared.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _delete_replication_group(ec, rg_id, shared):
    """Delete the group and wait every 2 s until it is gone. DeleteReplicationGroup answers
    InvalidReplicationGroupState while the group is creating, modifying or migrating, which is retried;
    a group already deleting is awaited. Any other failure, or the deadline passing, raises."""
    deadline = _deadline(shared)
    while True:
        try:
            groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
            if not groups:
                return
            if groups[0]["Status"] != "deleting":
                ec.delete_replication_group(ReplicationGroupId=rg_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code != "InvalidReplicationGroupState":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"replication group {rg_id} still present at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
