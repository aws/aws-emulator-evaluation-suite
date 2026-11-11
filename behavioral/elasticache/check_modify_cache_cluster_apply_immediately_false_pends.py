"""modify-cache-cluster-apply-immediately-false-pends."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cache-cluster-apply-immediately-false-pends"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']

_ENGINE = "memcached"
# cache.t3.micro is a cheap node type available for memcached in every commercial region.
_NODE_TYPE = "cache.t3.micro"
# How long a deferred modification must be observed to STAY deferred. This is a
# "remains true" window, not an assertion-by-sleep: the assertion is on the pending/applied
# split, and this loop only proves the split does not silently resolve itself.
_STAYS_PENDING_S = 6
_STAYS_PENDING_INTERVAL_S = 2


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error_code(fn):
    """Call fn(); return (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds, so a missing refusal is always loud.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _assert_error(fn, expected, expected_message, what):
    """Assert fn() fails with `expected` AND `expected_message`; return the code.

    The message is asserted because `InvalidParameterValue` is ElastiCache's catch-all: the
    same code answers an out-of-range node count, an unknown parameter and a bad value, so
    the code alone does not establish WHICH rule refused the call.
    """
    code, message = _error_code(fn)
    assert code is not None, f"{what}: expected {expected} but the call SUCCEEDED (over-permissive)"
    assert _fault_base(code) == _fault_base(expected), (
        f"{what}: expected {expected}, got {code} ({message!r})"
    )
    assert message == expected_message, (
        f"{what}: the refusal must name its own reason; expected {expected_message!r}, got "
        f"{message!r}"
    )
    return code


def _far_maintenance_windows():
    """Two one-hour maintenance windows on days three and four from today (UTC).

    The window must not open while the check runs: ElastiCache would start provisioning the
    pending nodes and refuse every later ModifyCacheCluster with InvalidParameterCombination.
    """
    days = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
    # time.gmtime().tm_wday is Monday=0; the `days` tuple above is Sunday=0.
    today = (time.gmtime().tm_wday + 1) % 7
    first = days[(today + 3) % 7]
    second = days[(today + 4) % 7]
    return f"{first}:03:00-{first}:04:00", f"{second}:05:00-{second}:06:00"


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


def _poll(probe, predicate, timeout_s=1500, interval_s=2, ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the polled state (last observed: {last!r}): the run budget "
                                   f"ended first; not graded")
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _describe_cluster(ec, cluster_id):
    return _describe_one(
        ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id
    )


def _pending(cluster):
    return (cluster or {}).get("PendingModifiedValues") or {}


def _delete_cluster_and_wait(ec, cluster_id, timeout_s=1500, interval_s=2, ctx=None):
    """Delete a cache cluster and poll it to actual disappearance.

    Registered at creation time. A cluster still `creating` or `modifying` refuses deletion
    with InvalidCacheClusterState, so this retries rather than leaking a billable node.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            break
        except ClientError as e:
            code = _fault_base(e.response.get("Error", {}).get("Code") or "")
            if code == "CacheClusterNotFound":
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                if code == "InvalidCacheClusterState" and ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"cache cluster {cluster_id} accepting DeleteCacheCluster: "
                                       f"the run budget ended first; not graded") from e
                raise
            time.sleep(interval_s)
    _poll(lambda: _describe_cluster(ec, cluster_id), lambda c: c is None,
          timeout_s=timeout_s, interval_s=interval_s, ctx=ctx)


def _assert_stays(probe, predicate, window_s, interval_s, what):
    """Assert predicate(probe()) holds for the whole window, sampling every interval_s."""
    deadline = time.monotonic() + window_s
    while True:
        observed = probe()
        assert predicate(observed), f"{what}: condition stopped holding (observed {observed!r})"
        if time.monotonic() >= deadline:
            return observed
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A disruptive ModifyCacheCluster with ApplyImmediately=False is parked in
    PendingModifiedValues (a later one replaces it, NumCacheNodes=0 is refused, 41 is parked) while
    a non-disruptive change applies at once; re-issuing the current node count cancels it.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheCluster.html
    """
    ec = ctx.client("elasticache")

    # ---- full valid setup ------------------------------------------------------------
    window_one, window_two = _far_maintenance_windows()
    assert window_one != window_two, (window_one, window_two)
    cluster_id = ctx.unique_name("sim2real-behav-ecc-pending-")
    subnet_group = _network_cache_subnet_group(ctx, ec)
    created = ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine=_ENGINE,
        CacheNodeType=_NODE_TYPE,
        NumCacheNodes=1,
        PreferredMaintenanceWindow=window_one,
        CacheSubnetGroupName=subnet_group,
    )["CacheCluster"]
    # Registered immediately, BEFORE the id is used for anything else, so nothing between
    # here and the first assertion can leak a billable node.
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ec, cluster_id))
    assert created["CacheClusterStatus"] == "creating", created["CacheClusterStatus"]

    cluster = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and c.get("CacheClusterStatus") == "available",
        timeout_s=_budget_s(ctx, 1500),
        ctx=ctx,
    )
    assert cluster["Engine"] == _ENGINE, cluster
    assert cluster["NumCacheNodes"] == 1, cluster
    assert _pending(cluster).get("NumCacheNodes") is None, (
        f"a freshly created cluster must have no pending node-count change, got "
        f"{_pending(cluster)}"
    )
    # The requested window must be honoured verbatim: the non-disruptive leg below modifies it, so
    # its starting value is pinned (see `_far_maintenance_windows`).
    assert cluster.get("PreferredMaintenanceWindow") == window_one, (
        f"CreateCacheCluster must honour the requested PreferredMaintenanceWindow "
        f"{window_one!r}, got {cluster.get('PreferredMaintenanceWindow')!r}"
    )

    # ---- the deferred modification is PARKED, not applied ---------------------------
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=2,
        ApplyImmediately=False,
    )
    parked = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") == 2,
        timeout_s=_budget_s(ctx, 300),
        interval_s=2,
        ctx=ctx,
    )
    assert parked["NumCacheNodes"] == 1, (
        f"ApplyImmediately=False was IGNORED: NumCacheNodes is already {parked['NumCacheNodes']} "
        f"at the top level; a deferred change must not take effect until the maintenance window"
    )
    nodes = ec.describe_cache_clusters(
        CacheClusterId=cluster_id, ShowCacheNodeInfo=True,
    )["CacheClusters"][0].get("CacheNodes", [])
    assert len(nodes) == 1, (
        f"ApplyImmediately=False was IGNORED: {len(nodes)} cache nodes actually exist, "
        f"expected 1 until the change is applied"
    )
    # A parked change does not move the cluster out of `available`; flipping to `modifying` would
    # mean work started that AWS has not started.
    assert parked["CacheClusterStatus"] == "available", (
        f"a DEFERRED modification must leave the cluster `available`, not begin applying; "
        f"status is {parked['CacheClusterStatus']!r}"
    )

    # ---- the split PERSISTS: it does not quietly resolve itself ---------------------
    _assert_stays(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None
        and c.get("NumCacheNodes") == 1
        and _pending(c).get("NumCacheNodes") == 2,
        _STAYS_PENDING_S,
        _STAYS_PENDING_INTERVAL_S,
        f"deferred NumCacheNodes=2 on {cluster_id} must stay pending, not be applied in the "
        f"background",
    )

    # ---- a second deferred modify REPLACES the pending one --------------------------
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=3,
        ApplyImmediately=False,
    )
    replaced = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") == 3,
        timeout_s=_budget_s(ctx, 300),
        interval_s=2,
        ctx=ctx,
    )
    assert replaced["NumCacheNodes"] == 1, (
        f"the replacement deferred modify was applied immediately: NumCacheNodes is "
        f"{replaced['NumCacheNodes']}"
    )

    # ---- break exactly one thing: an illegal deferred node count --------------------
    # NumCacheNodes carries no smithy.api#range trait, so botocore.validate passes 0 through
    # and the service is the only thing that can refuse it.
    for bad_count in (0, -1):
        _assert_error(
            lambda n=bad_count: ec.modify_cache_cluster(
                CacheClusterId=cluster_id,
                NumCacheNodes=n,
                ApplyImmediately=False,
            ),
            "InvalidParameterValueException",
            "NumCacheNodes must be greater than or equal to 1.",
            f"ModifyCacheCluster with NumCacheNodes={bad_count}",
        )

    # ---- effect absent: neither the live value NOR the parked value moved ------------
    after_reject = _describe_cluster(ec, cluster_id)
    assert after_reject is not None, "cluster vanished after a rejected ModifyCacheCluster"
    assert after_reject["NumCacheNodes"] == 1, (
        f"REJECTED ModifyCacheCluster changed the live node count to "
        f"{after_reject['NumCacheNodes']}"
    )
    assert _pending(after_reject).get("NumCacheNodes") == 3, (
        f"REJECTED ModifyCacheCluster clobbered the unrelated pending change: "
        f"PendingModifiedValues is now {_pending(after_reject)}, expected NumCacheNodes=3 to "
        f"still be parked"
    )
    assert after_reject.get("CacheClusterStatus") == "available", (
        f"a rejected modify must leave the cluster available, got "
        f"{after_reject.get('CacheClusterStatus')!r}"
    )

    # ---- the ACCEPTANCE boundary: the deferred value is NOT range-checked -------------
    # 41 is one more than the 40-node memcached ceiling, yet ElastiCache parks it: the only
    # defer-time rule on NumCacheNodes is the >= 1 floor asserted above. The nodes are never
    # provisioned, because the window is days away and the value is cancelled below.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=41,
        ApplyImmediately=False,
    )
    over = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") == 41,
        timeout_s=_budget_s(ctx, 300),
        interval_s=2,
        ctx=ctx,
    )
    assert over["NumCacheNodes"] == 1, (
        f"an out-of-range DEFERRED node count must not be applied: top-level NumCacheNodes is "
        f"{over['NumCacheNodes']}"
    )
    over_nodes = ec.describe_cache_clusters(
        CacheClusterId=cluster_id, ShowCacheNodeInfo=True,
    )["CacheClusters"][0].get("CacheNodes", [])
    assert len(over_nodes) == 1, (
        f"{len(over_nodes)} cache nodes exist after parking NumCacheNodes=41; expected 1"
    )

    # ---- ApplyImmediately is per-CHANGE, not per-REQUEST ------------------------------
    # A NON-disruptive change sent with ApplyImmediately=False is applied IMMEDIATELY and never
    # lands in PendingModifiedValues, while the parked node count stays parked.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        PreferredMaintenanceWindow=window_two,
        ApplyImmediately=False,
    )
    windowed = _describe_cluster(ec, cluster_id)
    assert windowed is not None, "cluster vanished after a maintenance-window modify"
    assert windowed.get("PreferredMaintenanceWindow") == window_two, (
        f"a NON-disruptive change must take effect immediately even with "
        f"ApplyImmediately=False: PreferredMaintenanceWindow is "
        f"{windowed.get('PreferredMaintenanceWindow')!r}, expected {window_two!r}"
    )
    assert "PreferredMaintenanceWindow" not in _pending(windowed), (
        f"a NON-disruptive change must not be parked: PendingModifiedValues is "
        f"{_pending(windowed)}"
    )
    assert _pending(windowed).get("NumCacheNodes") == 41, (
        f"the non-disruptive change must leave the parked DISRUPTIVE change alone: "
        f"PendingModifiedValues is {_pending(windowed)}, expected NumCacheNodes=41"
    )
    assert windowed["NumCacheNodes"] == 1, windowed["NumCacheNodes"]

    # ---- the cancel path works with ApplyImmediately=FALSE too ------------------------
    # Re-issuing the CURRENT node count is the documented way to cancel a pending scaling operation,
    # under either value of ApplyImmediately. It also means later transitions start from an empty
    # PendingModifiedValues rather than DECREASING a parked add, which ElastiCache refuses.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=1,
        ApplyImmediately=False,
    )
    uncancelled = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") is None,
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
        ctx=ctx,
    )
    assert uncancelled["NumCacheNodes"] == 1, uncancelled["NumCacheNodes"]
    assert uncancelled.get("PreferredMaintenanceWindow") == window_two, (
        f"cancelling the pending scale-out must not revert the applied maintenance window; "
        f"got {uncancelled.get('PreferredMaintenanceWindow')!r}"
    )

    # ---- control case, part 1: a further legal deferred modify still parks -----------
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=2,
        ApplyImmediately=False,
    )
    reparked = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") == 2,
        timeout_s=_budget_s(ctx, 300),
        interval_s=2,
        ctx=ctx,
    )
    assert reparked["NumCacheNodes"] == 1, reparked

    # ---- control case, part 2: re-issuing the CURRENT value cancels the pending change
    # This is the documented cancel path for a pending ElastiCache scaling operation.
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=1,
        ApplyImmediately=True,
    )
    cleared = _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") is None,
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
        ctx=ctx,
    )
    assert cleared["NumCacheNodes"] == 1, (
        f"cancelling the pending scale-out must leave the cluster at 1 node, got "
        f"{cleared['NumCacheNodes']}"
    )
    _assert_stays(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and _pending(c).get("NumCacheNodes") is None,
        _STAYS_PENDING_S,
        _STAYS_PENDING_INTERVAL_S,
        f"the cancelled pending change on {cluster_id} must stay cancelled",
    )

    _delete_cluster_and_wait(ec, cluster_id, timeout_s=_budget_s(ctx, 1500), ctx=ctx)
    assert _describe_cluster(ec, cluster_id) is None, f"{cluster_id} still resolves after delete"


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
