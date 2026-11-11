"""modify-replication-group-shard-configuration-invalid-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-replication-group-shard-configuration-invalid-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticache"]

# `sim2real:managed=true` is what an account cleanup discovers through the Resource
# Groups Tagging API, so a leftover replication group can be found and attributed to this
# check rather than to "some elasticache run".
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyReplicationGroupShardConfiguration that lowers NodeGroupCount without NodeGroupsToRemove
    or NodeGroupsToRetain is rejected with InvalidParameterCombination before any shard is touched."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-rgshard-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real shard-configuration validation test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumNodeGroups=2,
        AutomaticFailoverEnabled=True,
        Tags=_RESOURCE_TAGS,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ctx, rg_id))
    _wait_for_rg_status(ctx, rg_id, {"available"}, timeout_s=1500)
    baseline_shards = _shard_count(ctx, rg_id)
    assert baseline_shards == 2, f"expected 2 shards, got {baseline_shards}"

    def _reshard_underspecified():
        # Decreasing NodeGroupCount without NodeGroupsToRemove/NodeGroupsToRetain is
        # an inconsistent request: ElastiCache cannot know which shard to drop.
        ec.modify_replication_group_shard_configuration(
            ReplicationGroupId=rg_id,
            NodeGroupCount=1,
            ApplyImmediately=True,
        )

    code, message = _error(_reshard_underspecified)
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    assert message == (
        "Node groups to remove or node groups to retain must be specified for a scale-in "
        "call but not both."
    ), message

    # effect absent: shard count unchanged, no shard was touched
    unchanged_shards = _shard_count(ctx, rg_id)
    assert unchanged_shards == baseline_shards, (
        f"shard count changed despite rejection: {unchanged_shards} != {baseline_shards}"
    )

    # positive control: a consistent shard-count increase is accepted
    ec.modify_replication_group_shard_configuration(
        ReplicationGroupId=rg_id,
        NodeGroupCount=3,
        ApplyImmediately=True,
    )
    grown_shards = _wait_for_shard_count(ctx, rg_id, 3, timeout_s=1500)
    assert grown_shards == 3


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _wait_for_rg_status(ctx, rg_id, target_statuses, timeout_s=1500.0, interval_s=20.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = ec.describe_replication_groups(ReplicationGroupId=rg_id)
        groups = resp.get("ReplicationGroups", [])
        if groups:
            status = groups[0]["Status"]
            if status in target_statuses:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {target_statuses}, last status={status}")


def _shard_count(ctx, rg_id):
    ec = ctx.client("elasticache")
    resp = ec.describe_replication_groups(ReplicationGroupId=rg_id)
    return len(resp["ReplicationGroups"][0]["NodeGroups"])


def _wait_for_shard_count(ctx, rg_id, target_count, timeout_s=1500.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    count = None
    while time.monotonic() < deadline:
        count = _shard_count(ctx, rg_id)
        if count >= target_count:
            _wait_for_rg_status(ctx, rg_id, {"available"}, timeout_s=timeout_s)
            return count
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {target_count} shards, last={count}")


def _delete_replication_group(ctx, rg_id):
    ec = ctx.client("elasticache")
    try:
        _wait_for_rg_status(ctx, rg_id, {"available"}, timeout_s=1500)
    except AssertionError:
        pass
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
