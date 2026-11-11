"""shard-configuration-resize-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shard-configuration-resize-transitions"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyReplicationGroupShardConfiguration reports a cluster-mode group as 'modifying' in its
    own response, then the group settles 'available' with the requested node group count."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-behav-shard-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real shard resize state-machine check",
        Engine="redis",
        # Redis (cluster mode enabled) is not supported on T-family
        # (burstable) node types; use the smallest supported general-purpose
        # type instead. Automatic failover is mandatory for cluster-mode-
        # enabled replication groups -- real AWS rejects CreateReplicationGroup
        # outright (InvalidParameterValueException) if it is disabled here,
        # even with zero replicas per shard.
        CacheNodeType="cache.m5.large",
        NumNodeGroups=2,
        ReplicasPerNodeGroup=0,
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real-purpose", "Value": "shard-configuration-resize-transitions"}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id))

    initial = _wait_rg_status(ec, rg_id, {"available"}, timeout_s=1200)
    assert initial == "available", f"expected initial creation to settle on 'available', got {initial!r}"
    node_groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0][
        "NodeGroups"
    ]
    assert len(node_groups) == 2, f"expected 2 shards after creation, got {len(node_groups)}"

    resized = ec.modify_replication_group_shard_configuration(
        ReplicationGroupId=rg_id,
        NodeGroupCount=3,
        ApplyImmediately=True,
    )["ReplicationGroup"]
    assert resized["ReplicationGroupId"] == rg_id, resized
    # The mutating call's own response reports the group in resharding.
    assert resized["Status"] == "modifying", (
        f"expected the mutating call's own response to report 'modifying', got {resized['Status']!r}"
    )

    final_status = _wait_rg_status(ec, rg_id, {"available"}, timeout_s=1800)
    assert final_status == "available", f"expected resharding to converge on 'available', got {final_status!r}"
    final_groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0][
        "NodeGroups"
    ]
    assert len(final_groups) == 3, f"expected 3 shards after resharding, got {len(final_groups)}"


def _wait_rg_status(ec, rg_id: str, targets: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        status = groups[0]["Status"]
        if status in targets:
            return status
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached {targets}, last status={status}")


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
