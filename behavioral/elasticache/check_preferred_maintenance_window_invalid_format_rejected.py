"""preferred-maintenance-window-invalid-format-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "preferred-maintenance-window-invalid-format-rejected"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheCluster rejects a malformed PreferredMaintenanceWindow (wrong ddd:hh24:mi
    format) with InvalidParameterValue, leaves the cluster's existing window untouched, and a
    subsequent validly formatted modify still succeeds (positive control, same cluster)."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-pmwneg-")
    original_window = "tue:10:00-tue:11:00"

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        PreferredMaintenanceWindow=original_window,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cache_cluster_safe(ec, cluster_id))

    _poll_until(
        lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0],
        lambda c: c["CacheClusterStatus"] == "available",
        timeout_s=900.0,
        interval_s=15.0,
    )

    code, message = _error(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=cluster_id,
            PreferredMaintenanceWindow="not-a-valid-window",
            ApplyImmediately=True,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = (
        "Invalid maintenance window format. Should be specified as a range "
        "ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). Example: Sun:23:15-Mon:03:15"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) effect absent: the malformed modify must not have changed the stored window
    unchanged = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]
    assert unchanged["PreferredMaintenanceWindow"] == original_window, (
        f"window changed despite rejected modify: {unchanged['PreferredMaintenanceWindow']!r}"
    )

    # (c) positive control: a validly formatted window on the same cluster is accepted
    valid_new_window = "thu:02:00-thu:03:00"
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        PreferredMaintenanceWindow=valid_new_window,
        ApplyImmediately=True,
    )
    final = _poll_until(
        lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0],
        lambda c: c["CacheClusterStatus"] == "available"
        and c.get("PreferredMaintenanceWindow") == valid_new_window,
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert final["PreferredMaintenanceWindow"] == valid_new_window, (
        f"expected restored window {valid_new_window!r}, got "
        f"{final['PreferredMaintenanceWindow']!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected
    success raises, so acceptance never passes as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 900.0,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _delete_cache_cluster_safe(ec, cluster_id: str) -> None:
    """Delete the cluster, retrying while it is still creating or modifying; the subnet group's
    teardown then waits for the cluster to go, both inside the 1800 s cleanup budget."""
    _delete_when_released(
        lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id),
        ("InvalidCacheClusterState",),
        ("CacheClusterNotFound",),
        timeout_s=600.0,
        interval_s=2.0,
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
            timeout_s=1140.0,
            interval_s=2.0,
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a resource, retrying while it reports one of ``busy_codes``."""
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
