"""cache-cluster-not-found-semantics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-cluster-not-found-semantics"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describe, ListAllowedNodeTypeModifications, Modify, Reboot and Delete succeed on a real cache cluster,
    and on a deleted or never-created id fail with CacheClusterNotFound "CacheCluster not found: <id>", so
    not-found is a real lookup."""
    ec = ctx.client("elasticache")
    real_id = ctx.unique_name("sim2real-behav-ecc-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=real_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort_delete(ec, real_id))
    _wait_for_status(ec, real_id, {"available"}, timeout_s=600)

    # --- positive control: the same five operations succeed against a real id ---
    described = ec.describe_cache_clusters(CacheClusterId=real_id)["CacheClusters"]
    assert described and described[0]["CacheClusterId"] == real_id, described

    mods = ec.list_allowed_node_type_modifications(CacheClusterId=real_id)
    assert "ScaleUpModifications" in mods or "ScaleDownModifications" in mods, mods

    modified = ec.modify_cache_cluster(
        CacheClusterId=real_id,
        ApplyImmediately=True,
        PreferredMaintenanceWindow="sun:23:00-mon:00:30",
    )["CacheCluster"]
    assert modified["CacheClusterId"] == real_id, modified
    _wait_for_status(ec, real_id, {"available"}, timeout_s=120)

    rebooted = _reboot_when_idle(ec, real_id, timeout_s=300)
    assert rebooted["CacheClusterId"] == real_id, rebooted
    _wait_for_status(ec, real_id, {"available"}, timeout_s=180)

    ec.delete_cache_cluster(CacheClusterId=real_id)
    _wait_for_deleted(ec, real_id, timeout_s=600)
    # An independent read now finds the deleted cluster gone through the same
    # NotFound branch the negative control below exercises on an id that never existed.
    refused = _refusal(lambda: ec.describe_cache_clusters(CacheClusterId=real_id))
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {real_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"

    # --- negative control: a CacheClusterId that never existed at all ---
    bogus_id = ctx.unique_name("sim2real-behav-ecc-missing-")
    refused = _refusal(lambda: ec.delete_cache_cluster(CacheClusterId=bogus_id))
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {bogus_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"
    refused = _refusal(lambda: ec.describe_cache_clusters(CacheClusterId=bogus_id))
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {bogus_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=bogus_id, ApplyImmediately=True, NumCacheNodes=1,
        ),
    )
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {bogus_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.reboot_cache_cluster(
            CacheClusterId=bogus_id, CacheNodeIdsToReboot=["0001"],
        ),
    )
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {bogus_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"
    refused = _refusal(lambda: ec.list_allowed_node_type_modifications(CacheClusterId=bogus_id))
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {bogus_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _refusal(fn):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn)
    return _fault_base(code), message


def _wait_for_status(ec, cluster_id, targets, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
        if clusters:
            last = clusters[0]["CacheClusterStatus"]
            if last in targets:
                return clusters[0]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cache cluster {cluster_id} never reached {targets}, last status={last!r}"
            )
        time.sleep(interval_s)


def _wait_for_deleted(ec, cluster_id, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cache cluster {cluster_id} never became not-found within {timeout_s}s")
        time.sleep(interval_s)


def _reboot_when_idle(ec, cluster_id, timeout_s=300.0, interval_s=15.0):
    """Reboot node 0001, retrying while the preceding modify still holds the cluster's
    management lock (InvalidCacheClusterState); the cluster can read 'available' while it does."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec.reboot_cache_cluster(
                CacheClusterId=cluster_id, CacheNodeIdsToReboot=["0001"],
            )["CacheCluster"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if _fault_base(code) != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _best_effort_delete(ec, cluster_id):
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CacheClusterNotFound":
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
