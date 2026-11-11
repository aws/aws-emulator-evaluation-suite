"""modify-cache-cluster-pending-vs-immediate-application."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cache-cluster-pending-vs-immediate-application"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheCluster changing the cache parameter group without ApplyImmediately leaves the
    node(s) "pending-reboot" (the new group not yet in effect) until RebootCacheCluster applies it
    and the node becomes "in-sync"."""
    ec = ctx.client("elasticache")
    resource_tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:check", "Value": CHECK},
    ]
    group_a = ctx.unique_name("sim2real-pg-a-")
    group_b = ctx.unique_name("sim2real-pg-b-")
    for g in (group_a, group_b):
        ec.create_cache_parameter_group(
            CacheParameterGroupName=g,
            CacheParameterGroupFamily="memcached1.6",
            Description="sim2real pending-vs-immediate check",
            Tags=resource_tags,
        )
    # Give group_b a value different from the default so the switch is observable.
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=group_b,
        ParameterNameValues=[{"ParameterName": "chunk_size_growth_factor", "ParameterValue": "1.5"}],
    )

    cluster_id = ctx.unique_name("sim2real-pending-")
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheParameterGroupName=group_a,
        Tags=resource_tags,
        CacheSubnetGroupName=_network_cache_subnet_group(ctx, ec),
    )
    ctx.on_cleanup(lambda: _cleanup(ec, cluster_id, group_a, group_b))
    _wait_for_cluster_status(ec, cluster_id, {"available"}, timeout_s=900)

    # Switch the parameter group WITHOUT ApplyImmediately.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        CacheParameterGroupName=group_b,
        ApplyImmediately=False,
    )

    pending = _wait_for_apply_status(ec, cluster_id, {"pending-reboot"}, timeout_s=180)
    assert pending["CacheParameterGroup"]["CacheParameterGroupName"] == group_b, (
        "desired parameter group did not update even though it should be pending"
    )
    assert pending["CacheClusterStatus"] == "available", (
        f"cluster left 'available' state merely from queuing a pending change: {pending['CacheClusterStatus']!r}"
    )
    node_ids = pending["CacheParameterGroup"].get("CacheNodeIdsToReboot")
    assert node_ids, (
        f"a 'pending-reboot' parameter group must name the node(s) it needs rebooted, "
        f"got CacheNodeIdsToReboot={node_ids!r}"
    )

    ec.reboot_cache_cluster(CacheClusterId=cluster_id, CacheNodeIdsToReboot=node_ids)
    _wait_for_cluster_status(ec, cluster_id, {"available"}, timeout_s=300)

    applied = _wait_for_apply_status(ec, cluster_id, {"in-sync"}, timeout_s=180)
    assert applied["CacheParameterGroup"]["CacheParameterGroupName"] == group_b, (
        f"expected the applied group to still be {group_b!r}, got "
        f"{applied['CacheParameterGroup']['CacheParameterGroupName']!r}"
    )
    assert applied["CacheParameterGroup"]["ParameterApplyStatus"] == "in-sync", (
        f"expected ParameterApplyStatus 'in-sync' after RebootCacheCluster, got "
        f"{applied['CacheParameterGroup']['ParameterApplyStatus']!r}"
    )


def _describe(ec: Any, cluster_id: str) -> dict:
    return ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]


def _wait_for_cluster_status(ec: Any, cluster_id: str, targets: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe(ec, cluster_id)
        if last["CacheClusterStatus"] in targets:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets}; last={last}")


def _wait_for_apply_status(ec: Any, cluster_id: str, targets: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe(ec, cluster_id)
        status = last.get("CacheParameterGroup", {}).get("ParameterApplyStatus")
        if status in targets:
            return last
        time.sleep(2)
    raise AssertionError(f"ParameterApplyStatus for {cluster_id} never reached {targets}; last={last}")


def _cleanup(ec: Any, cluster_id: str, group_a: str, group_b: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("CacheClusterNotFound", "CacheClusterNotFoundFault"):
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("CacheClusterNotFound", "CacheClusterNotFoundFault"):
                break
            raise
        time.sleep(15)
    for g in (group_a, group_b):
        try:
            ec.delete_cache_parameter_group(CacheParameterGroupName=g)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("CacheParameterGroupNotFound", "CacheParameterGroupNotFoundFault"):
                raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
