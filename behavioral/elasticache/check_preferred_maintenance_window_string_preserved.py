"""preferred-maintenance-window-string-preserved."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "preferred-maintenance-window-string-preserved"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PreferredMaintenanceWindow values from create and ModifyCacheCluster read back verbatim.
    After deletion the cluster reads as gone and a modify on the dead id fails with not-found."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-pmw-")
    initial_window = "sun:23:00-mon:01:30"

    subnet_group = _network_cache_subnet_group(ctx, ec)
    create_resp = ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        PreferredMaintenanceWindow=initial_window,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cache_cluster_safe(ec, cluster_id))
    assert create_resp["CacheCluster"]["PreferredMaintenanceWindow"] == initial_window, (
        f"create echoed {create_resp['CacheCluster'].get('PreferredMaintenanceWindow')!r}, "
        f"expected {initial_window!r}"
    )

    _poll_until(
        lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0],
        lambda c: c["CacheClusterStatus"] == "available",
        timeout_s=900.0,
        interval_s=15.0,
    )

    new_window = "wed:04:00-wed:05:00"
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id, PreferredMaintenanceWindow=new_window, ApplyImmediately=True
    )

    final = _poll_until(
        lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0],
        lambda c: c["CacheClusterStatus"] == "available"
        and c.get("PreferredMaintenanceWindow") == new_window,
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert final["PreferredMaintenanceWindow"] == new_window, final.get("PreferredMaintenanceWindow")

    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _poll_until(
        lambda: _describe_or_gone(ec, cluster_id),
        lambda c: c is None,
        timeout_s=900.0,
        interval_s=15.0,
    )
    code, message = _error(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=cluster_id, PreferredMaintenanceWindow=new_window, ApplyImmediately=True
        )
    )
    assert code == "CacheClusterNotFound", (
        f"modify on a deleted cluster returned {code!r}, expected CacheClusterNotFound"
    )
    expected_message = f"CacheCluster not found: {cluster_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _describe_or_gone(ec, cluster_id: str) -> Any:
    from botocore.exceptions import ClientError

    try:
        return ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "CacheClusterNotFound":
            return None
        raise


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected
    success raises, so acceptance never passes as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
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
