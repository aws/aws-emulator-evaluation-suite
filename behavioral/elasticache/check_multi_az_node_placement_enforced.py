"""multi-az-node-placement-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from typing import Any

from behavioral_harness import tags

CHECK = "multi-az-node-placement-enforced"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Memcached cluster created with AZMode='cross-az' has its nodes spread across
    distinct Availability Zones by the managed placement policy."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-az-")[:50].rstrip("-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=2,
        AZMode="cross-az",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))

    cluster = _poll_until(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c["CacheClusterStatus"] == "available",
        timeout_s=600.0,
        interval_s=15.0,
    )

    nodes = cluster["CacheNodes"]
    assert len(nodes) == 2, f"expected 2 cache nodes, got {len(nodes)}"
    azs = {node["CustomerAvailabilityZone"] for node in nodes}
    assert len(azs) >= 2, (
        f"AZMode='cross-az' with 2 nodes must place them in distinct AZs, got {azs!r}"
    )




def _describe_cluster(ec, cluster_id: str) -> dict[str, Any]:
    return ec.describe_cache_clusters(CacheClusterId=cluster_id, ShowCacheNodeInfo=True)[
        "CacheClusters"
    ][0]


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
