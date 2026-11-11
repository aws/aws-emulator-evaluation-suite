"""decrease-replica-count-noop-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decrease-replica-count-noop-rejected"
GROUP = "concurrency"
SERVICES = ["elasticache"]


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DecreaseReplicaCount to the group's current replica count is rejected with NoOperationFault and its
    exact message and leaves one replica, while IncreaseReplicaCount on the same group then adds a second."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-noopdec-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="decrease-replica-count no-op rejection test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=2,  # 1 primary + 1 replica
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id))
    initial = _wait_rg_status(ec, rg_id, "available", timeout_s=1200)
    initial_replica_count = len(initial["NodeGroups"][0]["NodeGroupMembers"]) - 1
    assert initial_replica_count == 1, f"expected 1 replica after create, got {initial_replica_count}"

    code, message = _error(
        lambda: ec.decrease_replica_count(
            ReplicationGroupId=rg_id, NewReplicaCount=1, ApplyImmediately=True
        )
    )
    assert code == "NoOperationFault", f"no-op DecreaseReplicaCount failed with {code!r}, expected 'NoOperationFault'"
    assert message == "Requested new replica count already matches current number of replicas.", (
        f"unexpected NoOperationFault message: {message!r}"
    )

    unchanged = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    unchanged_replica_count = len(unchanged["NodeGroups"][0]["NodeGroupMembers"]) - 1
    assert unchanged_replica_count == 1, (
        f"replica count changed to {unchanged_replica_count} after a rejected no-op call, expected it to stay 1"
    )

    # Positive control: a real change on the same group still works.
    ec.increase_replica_count(ReplicationGroupId=rg_id, NewReplicaCount=2, ApplyImmediately=True)
    # The top-level Status can flip back to 'available' a moment before the newly-added
    # replica actually lands in NodeGroupMembers (the member list update lags the
    # group-level status transition on real ElastiCache), so poll for both conditions
    # together rather than trusting a single describe right after Status == 'available'.
    final = _wait_for_member_count(ec, rg_id, 3, timeout_s=1500)
    final_replica_count = len(final["NodeGroups"][0]["NodeGroupMembers"]) - 1
    assert final_replica_count == 2, (
        f"positive-control IncreaseReplicaCount left replica count at {final_replica_count}, expected 2"
    )


def _wait_rg_status(ec, rg_id, target_status, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups and groups[0]["Status"] == target_status:
            return groups[0]
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached status {target_status!r} within {timeout_s}s")


def _wait_for_member_count(ec, rg_id, expected, timeout_s=1500.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            rg = groups[0]
            last = rg
            members = rg["NodeGroups"][0]["NodeGroupMembers"]
            if rg["Status"] == "available" and len(members) == expected:
                return rg
        time.sleep(interval_s)
    raise AssertionError(
        f"replication group {rg_id} never converged to {expected} node group members "
        f"while available; last={last}"
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
