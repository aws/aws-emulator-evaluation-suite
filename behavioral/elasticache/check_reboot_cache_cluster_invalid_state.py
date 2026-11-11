"""reboot-cache-cluster-invalid-state."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert message == expected[1], f"expected message {expected[1]!r}, got {message!r}"
    return code

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _describe_cluster(ec, cluster_id):
    return _describe_one(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id)

def _wait_cluster_status(ec, cluster_id, status, timeout_s=1800, interval_s=15):
    return _wait_status(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterStatus", status, timeout_s, interval_s)

def _reboot_with_retry(ec, cluster_id, timeout_s=180, interval_s=5):
    """Reboot, tolerating the transient InvalidCacheClusterState real AWS can still answer
    for a few seconds right after CacheClusterStatus flips to 'available'."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec.reboot_cache_cluster(CacheClusterId=cluster_id, CacheNodeIdsToReboot=["0001"])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if _fault_base(code) != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _wait_cluster_gone(ec, cluster_id, timeout_s=900, interval_s=15):
    """Gone means either absent from describe or, per observed real-AWS behavior, present
    with a terminal 'deleted' status."""
    deadline = time.monotonic() + timeout_s
    while True:
        cluster = _describe_cluster(ec, cluster_id)
        if cluster is None or cluster.get("CacheClusterStatus") == "deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{cluster_id} still visible via describe {timeout_s}s after delete")
        time.sleep(interval_s)

def _best_effort_delete(ec, cluster_id):
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CacheClusterNotFound":
            raise

CHECK = "reboot-cache-cluster-invalid-state"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """RebootCacheCluster and CreateSnapshot on a creating cluster fail with
    InvalidCacheClusterStateFault and their exact messages; once available the reboot succeeds, and
    after the cluster is deleted a reboot fails with CacheClusterNotFoundFault."""
    ec = ctx.client("elasticache")
    cluster_id = ctx.unique_name("sim2real-behav-ecc-reboot-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort_delete(ec, cluster_id))

    cluster = _describe_cluster(ec, cluster_id)
    if cluster is not None and cluster.get("CacheClusterStatus") == "available":
        raise AssertionError(
            "cluster became available before reboot could be attempted while creating"
        )

    _assert_error(lambda: ec.reboot_cache_cluster(
        CacheClusterId=cluster_id, CacheNodeIdsToReboot=["0001"],
    ), ("InvalidCacheClusterStateFault", (
        "Can only reboot cache clusters with state in: available, incompatible-parameters, "
        f"snapshotting. Cluster {cluster_id} has state: creating.")
    ))

    # A creating cluster also cannot be snapshotted.
    _assert_error(lambda: ec.create_snapshot(
        CacheClusterId=cluster_id, SnapshotName=ctx.unique_name("sim2real-behav-ecs-early-"),
    ), ("InvalidCacheClusterStateFault", "Cluster must be in available state in order to create a snapshot."))

    _wait_cluster_status(ec, cluster_id, "available", timeout_s=1500)

    # Positive control: the identical call now succeeds now that the state barrier is lifted.
    _reboot_with_retry(ec, cluster_id)

    # RebootCacheCluster is itself asynchronous: it moves the cluster into "rebooting cache
    # cluster nodes", a state that (like "creating") rejects DeleteCacheCluster. Wait for the
    # reboot to finish and the cluster to settle back to "available" before deleting it.
    _wait_cluster_status(ec, cluster_id, "available", timeout_s=600)

    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _wait_cluster_gone(ec, cluster_id, timeout_s=900)
    _assert_error(lambda: ec.reboot_cache_cluster(
        CacheClusterId=cluster_id, CacheNodeIdsToReboot=["0001"],
    ), ("CacheClusterNotFoundFault", f"CacheCluster not found: {cluster_id}"))


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
