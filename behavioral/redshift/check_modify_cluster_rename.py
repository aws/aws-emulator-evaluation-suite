"""modify-cluster-rename."""

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
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
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
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        # Encrypted at rest, as a customer would configure it.
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


# One deadline shared by all of the check's teardowns, inside the suite's 1800 s cleanup budget.
_TEARDOWN_S = 1740.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _delete_cluster(ctx, rs, *cluster_ids):
    """Teardown for a cluster that may sit under either of its ids mid-rename: until none of them
    resolves, DeleteCluster each id that does, retrying InvalidClusterState (creating or being renamed)
    and polling every 2 s, all to the shared deadline."""
    deadline = _deadline(ctx)
    while True:
        live = [cid for cid in cluster_ids if _cluster_status(rs, cid) is not None]
        if not live:
            return
        for cid in live:
            if _cluster_status(rs, cid) == "deleting":
                continue
            try:
                rs.delete_cluster(ClusterIdentifier=cid, SkipFinalClusterSnapshot=True)
            except ClientError as exc:
                if _code_of(exc) not in _NOT_FOUND_CLUSTER and _code_of(exc) != "InvalidClusterState":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {live!r} still present at the teardown deadline")
        time.sleep(2)

CHECK = "modify-cluster-rename"
GROUP = 'cluster-lifecycle'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCluster with NewClusterIdentifier moves identity: old id stops resolving, new id resolves."""
    rs = ctx.client("redshift")
    old_id = ctx.unique_name("sim2real-behav-rs-old-")
    new_id = ctx.unique_name("sim2real-behav-rs-new-")
    ctx.on_cleanup(lambda: _delete_cluster(ctx, rs, new_id, old_id))
    rs.create_cluster(**_cluster_params(rs, old_id))
    _wait_for_cluster_available(rs, old_id, timeout_s=540)

    renamed = rs.modify_cluster(ClusterIdentifier=old_id, NewClusterIdentifier=new_id)["Cluster"]
    assert renamed["ClusterIdentifier"] == new_id, f"expected renamed identifier, got {renamed['ClusterIdentifier']}"

    _wait_until(
        lambda: _cluster_status(rs, old_id),
        lambda s: s is None,
        timeout_s=240,
        interval_s=15,
        what="old cluster identifier to stop resolving",
    )
    try:
        _retrying(lambda: rs.describe_clusters(ClusterIdentifier=old_id))
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        raise AssertionError(f"DescribeClusters still resolves the old identifier {old_id!r}")
    assert error["Code"] == "ClusterNotFound", f"expected ClusterNotFound for the old identifier, got {error['Code']}"
    assert error["Message"] == f"Cluster {old_id} not found.", error["Message"]

    moved = _describe_cluster(rs, new_id)
    assert moved["ClusterIdentifier"] == new_id, f"expected new identifier {new_id!r} to resolve, got {moved['ClusterIdentifier']!r}"
    assert moved["MasterUsername"] == ADMIN_USERNAME, "rename must preserve cluster identity/config"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
