"""server-side-maintenance-window-enforced."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-maintenance-window-enforced"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheCluster rejects a PreferredMaintenanceWindow outside ddd:hh24:mi-ddd:hh24:mi with
    InvalidParameterValue and leaves the stored window untouched, while a well-formed window on
    the same cluster is accepted and persisted (positive control)."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-mw-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        PreferredMaintenanceWindow="mon:04:00-mon:05:00",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(ec, cluster_id))
    _wait_for_cluster_status(ec, cluster_id, {"available"}, timeout_s=900)

    # Positive control: a well-formed cross-day-capable window is accepted and persisted.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        PreferredMaintenanceWindow="tue:04:00-tue:05:00",
        ApplyImmediately=True,
    )
    _wait_for_field(
        ec, cluster_id, "PreferredMaintenanceWindow", "tue:04:00-tue:05:00", timeout_s=180
    )

    # Negative: a malformed window is rejected and must not mutate the stored value.
    code, message = _error(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=cluster_id,
            PreferredMaintenanceWindow="not-a-valid-window",
            ApplyImmediately=True,
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code {code!r} ({message!r})"
    expected_message = (
        "Invalid maintenance window format. Should be specified as a range "
        "ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). Example: Sun:23:15-Mon:03:15"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    current = _describe(ec, cluster_id)["PreferredMaintenanceWindow"]
    assert current == "tue:04:00-tue:05:00", (
        f"malformed maintenance window was rejected but the field still changed to {current!r}"
    )


# ===== helpers =====
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


def _wait_for_field(ec: Any, cluster_id: str, field: str, value: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe(ec, cluster_id).get(field)
        if last == value:
            return
        time.sleep(2)
    raise AssertionError(f"{field} never became {value!r}; last observed {last!r}")


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_cluster(ec: Any, cluster_id: str) -> None:
    """Delete the cluster (retried while it is still modifying) and wait up to 600 s for it to go;
    with the subnet group's teardown it fits the 1800 s cleanup budget."""
    deadline = time.monotonic() + 600
    _delete_when_released(
        lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id),
        ("InvalidCacheClusterState",),
        ("CacheClusterNotFound", "CacheClusterNotFoundFault"),
        timeout_s=600.0,
        interval_s=2.0,
    )
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("CacheClusterNotFound", "CacheClusterNotFoundFault"):
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cache cluster {cluster_id} was not deleted within 600 s")


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
