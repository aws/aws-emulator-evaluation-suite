"""maintenance-window-scheduling-enforced."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-scheduling-enforced"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A well-formed PreferredMaintenanceWindow is persisted as given, a malformed one is rejected with
    InvalidParameterValue and the exact format message leaving the window unchanged, and a later well-formed
    window takes effect."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-maint-")[:50].rstrip("-")
    initial_window = "sun:22:00-sun:23:00"

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        PreferredMaintenanceWindow=initial_window,
        Tags=[{"Key": "sim2real", "Value": cluster_id}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))

    cluster = _poll_until(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c["CacheClusterStatus"] == "available",
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert cluster["PreferredMaintenanceWindow"] == initial_window, (
        f"well-formed maintenance window not persisted as given: "
        f"{cluster['PreferredMaintenanceWindow']!r}"
    )

    code, message = _error(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=cluster_id,
            PreferredMaintenanceWindow="notaday:99:99-notaday:100:00",
            ApplyImmediately=True,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = (
        "Invalid maintenance window format. Should be specified as a range "
        "ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). Example: Sun:23:15-Mon:03:15"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = _describe_cluster(ec, cluster_id)
    assert unchanged["PreferredMaintenanceWindow"] == initial_window, (
        "malformed maintenance window request must not alter the cluster's schedule"
    )

    valid_new_window = "mon:05:00-mon:06:00"
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        PreferredMaintenanceWindow=valid_new_window,
        ApplyImmediately=True,
    )
    updated = _poll_until(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c["PreferredMaintenanceWindow"] == valid_new_window,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert updated["PreferredMaintenanceWindow"] == valid_new_window, (
        f"subsequent well-formed modification did not take effect: expected "
        f"{valid_new_window!r}, got {updated['PreferredMaintenanceWindow']!r}"
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
