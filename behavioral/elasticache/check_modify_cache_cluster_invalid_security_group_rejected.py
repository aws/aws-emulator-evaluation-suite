"""modify-cache-cluster-invalid-security-group-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cache-cluster-invalid-security-group-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheCluster naming a cache security group is rejected with InvalidParameterValue "Use of cache
    security groups is not permitted in this API version for your account." and leaves the cluster available
    with the earlier AutoMinorVersionUpgrade=False change in place."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-badsg-")[:50].rstrip("-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        AutoMinorVersionUpgrade=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))

    _poll_until(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c["CacheClusterStatus"] == "available",
        timeout_s=600.0,
        interval_s=15.0,
    )

    # Positive control: a well-formed modification on the same cluster succeeds.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        AutoMinorVersionUpgrade=False,
        ApplyImmediately=True,
    )
    controlled = _poll_until(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c["AutoMinorVersionUpgrade"] is False,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert controlled["AutoMinorVersionUpgrade"] is False, (
        f"expected AutoMinorVersionUpgrade=False after the positive-control modify, "
        f"got {controlled['AutoMinorVersionUpgrade']!r}"
    )

    # Negative: an unresolvable cache security group name is rejected.
    code, message = _error(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=cluster_id,
            CacheSecurityGroupNames=["sim2real-nonexistent-cache-sg"],
            ApplyImmediately=True,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = "Use of cache security groups is not permitted in this API version for your account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the cluster's known-good state from the positive control persists.
    unaffected = _describe_cluster(ec, cluster_id)
    assert unaffected["AutoMinorVersionUpgrade"] is False, (
        "the rejected security-group modification must not alter unrelated cluster state"
    )
    assert unaffected["CacheClusterStatus"] == "available", (
        f"expected CacheClusterStatus='available' after the rejected modify, "
        f"got {unaffected['CacheClusterStatus']!r}"
    )


def _describe_cluster(ec, cluster_id: str) -> dict[str, Any]:
    return ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
