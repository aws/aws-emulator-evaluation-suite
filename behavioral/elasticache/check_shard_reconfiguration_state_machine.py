"""shard-reconfiguration-state-machine."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shard-reconfiguration-state-machine"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyReplicationGroupShardConfiguration moves a cluster-mode-enabled replication
    group into 'modifying' (resharding) and a second, conflicting reshard request is
    rejected until the first one completes."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-shard-")

    # One shared wall-clock budget covers both "wait for available" polls; each wait gets
    # only what is left of it, so a slow create cannot starve the reshard wait and the two
    # waits together stay within an 1800s limit.
    _budget_start = time.monotonic()
    _CHECK_BUDGET_S = 1700.0  # margin below the 1800s limit

    def _remaining_budget(reserve_s: float = 0.0) -> float:
        left = _CHECK_BUDGET_S - (time.monotonic() - _budget_start) - reserve_s
        return max(30.0, left)

    # The create-wait is capped at a fixed bound and a floor of the shared budget is
    # reserved for the reshard-wait, so a slow create cannot starve the shrink reshard
    # (reslot the removed shard's range onto the survivor and decommission its nodes).
    _CREATE_WAIT_CAP_S = 700.0
    _CREATE_WAIT_RESERVE_S = 900.0  # floor left for the reshard-wait below

    # Start from the minimum cluster-mode-enabled topology (2 shards, 1 replica each) and
    # SHRINK to 1: it exercises the same reshard state machine (modifying while applying,
    # a conflicting request rejected, converges back to available) with the fewest nodes
    # to provision. ElastiCache refuses a cluster-mode-enabled create with NumNodeGroups=1,
    # with ReplicasPerNodeGroup=0 / AutomaticFailoverEnabled=false, and on T-family micro
    # nodes, hence cache.m5.large with automatic failover. EngineVersion is left unpinned.
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="shard reconfiguration check",
        Engine="redis",
        CacheParameterGroupName="default.redis7.cluster.on",
        CacheNodeType="cache.m5.large",
        NumNodeGroups=2,
        ReplicasPerNodeGroup=1,
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort_delete(ec, rg_id))
    # Cap the create-wait at a fixed, generous bound (rather than letting it float up to
    # nearly the whole shared budget) so the reshard wait below always gets a large,
    # predictable minimum share of the remaining budget regardless of how long create
    # actually takes -- but reserve a floor for the reshard-wait so a slow create can't
    # starve it entirely.
    rg = _wait_for_rg_status(
        ec,
        rg_id,
        {"available"},
        timeout_s=min(_CREATE_WAIT_CAP_S, _remaining_budget(reserve_s=_CREATE_WAIT_RESERVE_S)),
        interval_s=10,
    )
    assert len(rg["NodeGroups"]) == 2, (
        f"expected 2 node groups after create, got {len(rg['NodeGroups'])}: {rg['NodeGroups']}"
    )

    # Begin a reshard: shrink from 2 shards to 1.
    # A decrease of NodeGroupCount must name NodeGroupsToRemove or NodeGroupsToRetain, or
    # ElastiCache refuses it with InvalidParameterCombination; remove the last (empty) shard.
    node_group_to_remove = rg["NodeGroups"][-1]["NodeGroupId"]
    ec.modify_replication_group_shard_configuration(
        ReplicationGroupId=rg_id,
        NodeGroupCount=1,
        ApplyImmediately=True,
        NodeGroupsToRemove=[node_group_to_remove],
    )

    # A second, conflicting reshard request must be rejected while the first is applying.
    # The conflicting request is an INCREASE (NodeGroupCount=3), which needs no
    # NodeGroupsToRemove/Retain, so it is well-formed on its own and its refusal can only
    # come from the group already being mid-reshard (InvalidReplicationGroupState).
    code, message = _error(
        lambda: ec.modify_replication_group_shard_configuration(
            ReplicationGroupId=rg_id, NodeGroupCount=3, ApplyImmediately=True
        )
    )
    assert code == "InvalidReplicationGroupState", (
        f"expected the conflicting reshard to be rejected with InvalidReplicationGroupState, "
        f"got {code!r} ({message!r})"
    )
    assert message == "Replication group must be in available state to modify.", (
        f"expected the exact InvalidReplicationGroupState message, got {message!r}"
    )

    # The reshard wait draws whatever is left of the shared budget: since the create-wait
    # above is capped well below the total budget, this is guaranteed a large minimum
    # (budget - cap) regardless of how long create actually took, while the whole check's
    # total wall-clock time still can never exceed the shared ceiling.
    rg = _wait_for_rg_status(
        ec, rg_id, {"available"}, timeout_s=_remaining_budget(), interval_s=10
    )
    assert len(rg["NodeGroups"]) == 1, (
        f"expected 1 node group after the shrink reshard converged, got {len(rg['NodeGroups'])}: "
        f"{rg['NodeGroups']} (a count of 3 here would mean the rejected conflicting reshard "
        f"was not actually rejected)"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the conflicting reshard request to be rejected, but it SUCCEEDED: {result!r}"
    )


def _wait_for_rg_status(ec, rg_id, targets, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            last = groups[0]["Status"]
            if last in targets:
                return groups[0]
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {targets}, last status={last}")


def _best_effort_delete(ec, rg_id):
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault",)
            or (exc.response["Error"]["Code"] == "InvalidReplicationGroupState" and "has status deleting" in exc.response["Error"].get("Message", ""))
        ):
            raise


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
