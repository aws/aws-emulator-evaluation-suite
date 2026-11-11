"""usage-limit-lifecycle."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}


def _wait_until(probe, done, timeout_s=600, interval_s=15, what="condition"):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
PARAM_FAMILY = "redshift-1.0"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id, **overrides):
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=MASTER_USERNAME,
        MasterUserPassword=MASTER_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        # This account requires encryption at rest.
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    params.update(overrides)
    return params


def _describe_cluster(rs, cluster_id):
    resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _cluster_status(rs, cluster_id):
    try:
        cluster = _describe_cluster(rs, cluster_id)
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    return cluster["ClusterStatus"] if cluster else None


def _wait_for_cluster_status(rs, cluster_id, target_statuses, timeout_s=600, interval_s=15):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in targets)}",
    )


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_for_cluster_status(rs, cluster_id, terminal, timeout_s=timeout_s)
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_for_cluster_gone(rs, cluster_id, timeout_s=420, interval_s=15):
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} to disappear",
    )


def _delete_cluster(rs, cluster_id):
    """Teardown: a cluster still 'creating' may refuse deletion, so
    retry within a bounded window."""
    deadline = time.time() + 240
    while True:
        try:
            _retrying(lambda: rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.time() >= deadline:
                raise
        time.sleep(2)

def _delete_usage_limit(rs, usage_limit_id):
    """Teardown: UsageLimitNotFound means already gone (the body deletes one limit itself)."""
    try:
        _retrying(lambda: rs.delete_usage_limit(UsageLimitId=usage_limit_id))
    except ClientError as exc:
        if _code_of(exc) != "UsageLimitNotFound":
            raise


CHECK = "usage-limit-lifecycle"
GROUP = 'usage-limit'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Usage limit create -> modify -> delete: a duplicate (cluster, feature, type, period) limit is
    accepted with its own id; after delete a lookup by id returns an empty list while a modify
    faults with UsageLimitNotFound.
    """
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-ulimit-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id, timeout_s=600)

    created = rs.create_usage_limit(
        ClusterIdentifier=cluster_id,
        FeatureType="concurrency-scaling",
        LimitType="time",
        Amount=60,
        Period="monthly",
        BreachAction="log",
    )
    usage_limit_id = created["UsageLimitId"]
    ctx.on_cleanup(lambda: _delete_usage_limit(rs, usage_limit_id))
    assert created["ClusterIdentifier"] == cluster_id
    assert created["Amount"] == 60
    assert created["Period"] == "monthly"
    assert created["BreachAction"] == "log"

    listed = rs.describe_usage_limits(ClusterIdentifier=cluster_id)["UsageLimits"]
    assert [u["UsageLimitId"] for u in listed] == [usage_limit_id], listed

    modified = rs.modify_usage_limit(UsageLimitId=usage_limit_id, Amount=120)
    assert modified["Amount"] == 120
    assert rs.describe_usage_limits(UsageLimitId=usage_limit_id)["UsageLimits"][0]["Amount"] == 120

    # Same cluster/feature/limit-type/period again: accepted, with a distinct id.
    second = rs.create_usage_limit(
        ClusterIdentifier=cluster_id,
        FeatureType="concurrency-scaling",
        LimitType="time",
        Amount=90,
        Period="monthly",
        BreachAction="log",
    )
    second_id = second["UsageLimitId"]
    ctx.on_cleanup(lambda: _delete_usage_limit(rs, second_id))
    assert second_id != usage_limit_id, "a second usage limit must get its own id"
    both = {
        u["UsageLimitId"]: u["Amount"]
        for u in rs.describe_usage_limits(ClusterIdentifier=cluster_id)["UsageLimits"]
    }
    assert both == {usage_limit_id: 120, second_id: 90}, both

    rs.delete_usage_limit(UsageLimitId=usage_limit_id)
    codes = {
        "modify-after-delete": _err(
            lambda: rs.modify_usage_limit(UsageLimitId=usage_limit_id, Amount=1)
        ),
        "describe-after-delete": _err(
            lambda: rs.describe_usage_limits(UsageLimitId=usage_limit_id)
        ),
    }
    expected = {
        "modify-after-delete": "UsageLimitNotFound",
        "describe-after-delete": "OK",
    }
    assert codes == expected, (
        f"usage-limit post-delete contract drift:\n expected={expected}\n observed={codes}"
    )
    assert rs.describe_usage_limits(UsageLimitId=usage_limit_id)["UsageLimits"] == [], (
        "a deleted usage limit must not be returned"
    )
    remaining = rs.describe_usage_limits(ClusterIdentifier=cluster_id)["UsageLimits"]
    assert [u["UsageLimitId"] for u in remaining] == [second_id], (
        f"deleting one limit must leave the other intact, got {remaining}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
