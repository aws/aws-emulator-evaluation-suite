"""automatic-failover-promotes-replica."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automatic-failover-promotes-replica"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TestFailover on a group with AutomaticFailoverEnabled and MultiAZEnabled promotes the
    replica to primary on its own (ElastiCache has no promote API), keeping both members."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-fo-")[:40].rstrip("-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real automatic failover behavioral check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=2,
        AutomaticFailoverEnabled=True,
        # Without MultiAZEnabled, TestFailover can return 200 without swapping the primary.
        MultiAZEnabled=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id)))

    rg = _poll_until(
        lambda: _describe_rg(ec, rg_id),
        lambda r: r["Status"] == "available",
        timeout_s=900.0,
        interval_s=20.0,
    )
    node_group = rg["NodeGroups"][0]
    node_group_id = node_group["NodeGroupId"]
    original_primary = _primary_cluster_id(node_group)
    assert original_primary is not None, "no primary member found before failover"
    assert len(node_group["NodeGroupMembers"]) == 2, (
        f"expected 2 members before failover, got {len(node_group['NodeGroupMembers'])}"
    )

    ec.test_failover(ReplicationGroupId=rg_id, NodeGroupId=node_group_id)

    def _failover_settled():
        r = _describe_rg(ec, rg_id)
        ng = next(g for g in r["NodeGroups"] if g["NodeGroupId"] == node_group_id)
        return r, ng

    def _role_changed(state):
        r, ng = state
        if r["Status"] != "available" or ng["Status"] != "available":
            return False
        # The node group returns to "available" before CurrentRole updates; poll for the swap.
        return _primary_cluster_id(ng) not in (None, original_primary)

    final_state = _poll_until(_failover_settled, _role_changed, timeout_s=600.0, interval_s=15.0)
    _, final_ng = final_state
    assert len(final_ng["NodeGroupMembers"]) == 2, "a member was lost during failover"
    new_primary = _primary_cluster_id(final_ng)
    assert new_primary is not None, "no primary member found after failover"
    assert new_primary != original_primary, (
        f"TestFailover completed but primary did not change ({original_primary!r}); "
        "the control plane must promote the replica on its own"
    )




def _describe_rg(ec, rg_id: str) -> dict[str, Any]:
    return ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]


def _primary_cluster_id(node_group: dict[str, Any]) -> str | None:
    for member in node_group["NodeGroupMembers"]:
        if member.get("CurrentRole") == "primary":
            return member["CacheClusterId"]
    return None


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault",)
            or (exc.response["Error"]["Code"] == "InvalidReplicationGroupState" and "has status deleting" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _poll_until(probe, predicate, timeout_s: float = 600.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
