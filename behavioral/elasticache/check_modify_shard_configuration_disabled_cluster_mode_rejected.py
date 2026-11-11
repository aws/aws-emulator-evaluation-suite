"""modify-shard-configuration-disabled-cluster-mode-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "modify-shard-configuration-disabled-cluster-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyReplicationGroupShardConfiguration only applies to Valkey/Redis OSS
    (cluster mode enabled) replication groups. Calling it on a (cluster mode
    disabled) group is rejected with an explicit parameter error, not a no-op."""
    ec = ctx.client("elasticache")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    disabled_rg_id = ctx.unique_name("sim2real-ecdis-")
    created = []
    ctx.on_cleanup(lambda: _delete_rgs(ec, created))

    ec.create_replication_group(
        ReplicationGroupId=disabled_rg_id,
        ReplicationGroupDescription="sim2real behavioral check: cluster-mode-disabled reshard",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    created.append(disabled_rg_id)
    # The cluster-mode-enabled control group is created up front so both creates overlap.
    enabled_rg_id = ctx.unique_name("sim2real-ecena-")
    ec.create_replication_group(
        ReplicationGroupId=enabled_rg_id,
        ReplicationGroupDescription="sim2real behavioral check: cluster-mode-enabled reshard",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumNodeGroups=2,
        ReplicasPerNodeGroup=0,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    created.append(enabled_rg_id)
    disabled_group = _wait_replication_group_available(ec, disabled_rg_id, timeout_s=900.0)
    assert disabled_group["ClusterEnabled"] is False, (
        f"expected cluster-mode-disabled group, ClusterEnabled={disabled_group['ClusterEnabled']!r}"
    )
    before_shard_count = len(disabled_group["NodeGroups"])

    code, message = _error(
        lambda: ec.modify_replication_group_shard_configuration(
            ReplicationGroupId=disabled_rg_id, NodeGroupCount=2, ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "Operation is only applicable for cluster mode enabled replication groups.", message

    # Effect absent: shard count and status unchanged on the cluster-mode-disabled group.
    after_reject = _replication_group(ec, disabled_rg_id)
    assert len(after_reject["NodeGroups"]) == before_shard_count, (
        f"shard count changed despite rejection: {len(after_reject['NodeGroups'])} != {before_shard_count}"
    )
    assert after_reject["Status"] == "available", (
        f"expected status unchanged at 'available' after rejection, got {after_reject['Status']!r}"
    )

    # Positive control: the SAME operation succeeds on a cluster-mode ENABLED group.
    enabled_group = _wait_replication_group_available(ec, enabled_rg_id, timeout_s=900.0)
    assert enabled_group["ClusterEnabled"] is True, (
        f"expected cluster-mode-enabled group, ClusterEnabled={enabled_group['ClusterEnabled']!r}"
    )
    assert len(enabled_group["NodeGroups"]) == 2, (
        f"expected 2 node groups on cluster-mode-enabled control group, got {len(enabled_group['NodeGroups'])}"
    )

    ec.modify_replication_group_shard_configuration(
        ReplicationGroupId=enabled_rg_id, NodeGroupCount=3, ApplyImmediately=True
    )
    # The accepted reshard is graded at its terminal state: the group settles back at
    # "available" with three node groups.
    resharded = _poll_until(
        lambda: _replication_group(ec, enabled_rg_id),
        lambda group: group["Status"] == "available" and len(group["NodeGroups"]) == 3,
        timeout_s=1500.0,
        interval_s=20.0,
    )
    assert len(resharded["NodeGroups"]) == 3, (
        f"accepted ModifyReplicationGroupShardConfiguration did not add a shard, "
        f"node groups={len(resharded['NodeGroups'])}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _replication_group(ec, rg_id):
    groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    if not groups:
        raise AssertionError(f"replication group {rg_id!r} disappeared unexpectedly")
    return groups[0]


def _wait_replication_group_available(ec, rg_id, timeout_s=900.0):
    return _poll_until(
        lambda: _replication_group(ec, rg_id),
        lambda group: group["Status"] == "available",
        timeout_s=timeout_s,
        interval_s=15.0,
    )


def _delete_rgs(ec, rg_ids):
    """Teardown: delete every group once it accepts the delete, then wait until all are gone.

    The deletes are issued together so the groups delete in parallel. A group still creating
    or resharding refuses DeleteReplicationGroup with InvalidReplicationGroupState, so that
    code is retried within a bounded window.
    """
    pending = list(rg_ids)
    deadline = time.monotonic() + 1800.0
    while pending:
        for rg_id in list(pending):
            try:
                ec.delete_replication_group(ReplicationGroupId=rg_id)
                pending.remove(rg_id)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ReplicationGroupNotFoundFault":
                    pending.remove(rg_id)
                elif code != "InvalidReplicationGroupState" or time.monotonic() >= deadline:
                    raise
        if pending:
            time.sleep(20)
    remaining = list(rg_ids)
    deadline = time.monotonic() + 1200.0
    while remaining and time.monotonic() < deadline:
        for rg_id in list(remaining):
            try:
                ec.describe_replication_groups(ReplicationGroupId=rg_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ReplicationGroupNotFoundFault":
                    raise
                remaining.remove(rg_id)
        if remaining:
            time.sleep(20)
    if remaining:
        raise AssertionError(f"replication groups {remaining!r} were not deleted within 1200s")


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

    The 1500 s window fits this suite's 1800 s teardown budget.
    """
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
