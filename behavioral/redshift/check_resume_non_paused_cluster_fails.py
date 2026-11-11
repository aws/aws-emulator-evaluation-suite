"""resume-non-paused-cluster-fails."""

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


def _error(fn):
    """Call *fn* and return the (code, message) of the AWS error it raises; a success fails."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded where AWS rejects it")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s=600, interval_s=2, what="condition", ctx=None):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
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


def _wait_for_cluster_status(rs, cluster_id, target_statuses, timeout_s=600, interval_s=2, ctx=None):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"cluster {cluster_id} status in {sorted(str(t) for t in targets)}",
        ctx=ctx,
    )


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600, ctx=None):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_for_cluster_status(rs, cluster_id, terminal, timeout_s=timeout_s, ctx=ctx)
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_for_cluster_gone(rs, cluster_id, timeout_s=420, interval_s=2):
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


_NOT_FOUND_SNAPSHOT = ("ClusterSnapshotNotFound", "ClusterSnapshotNotFoundFault")


def _snapshot_status(rs, snapshot_id):
    try:
        resp = _retrying(
            lambda: rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)
        )
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
            return None
        raise
    snapshots = resp.get("Snapshots", [])
    return snapshots[0]["Status"] if snapshots else None


def _wait_for_snapshot_available(rs, snapshot_id, timeout_s=240, interval_s=2, ctx=None):
    return _wait_until(
        lambda: _snapshot_status(rs, snapshot_id),
        lambda s: s == "available",
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"snapshot {snapshot_id} to become available",
        ctx=ctx,
    )


def _pause_when_active(rs, cluster_id, timeout_s=180, interval_s=2, ctx=None):
    """PauseCluster additionally requires the cluster be ACTIVE, which briefly lags
    the snapshot that unblocks it (real AWS: 'You can only pause an ACTIVE Cluster'
    even once ClusterStatus already reads 'available'). Bounded retry, not a sleep."""
    deadline = time.time() + timeout_s
    while True:
        try:
            rs.pause_cluster(ClusterIdentifier=cluster_id)
            return
        except ClientError as exc:
            if _code_of(exc) != "InvalidClusterState":
                raise
            if time.time() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"PauseCluster {cluster_id} accepted: the run budget ended first; not graded") from exc
                raise
            time.sleep(interval_s)


def _delete_snapshot(rs, cluster_id, snapshot_id):
    """Best-effort teardown: independent of cluster lifecycle, so attempt it
    regardless of whether the cluster delete has already run."""
    deadline = time.time() + 120
    while True:
        try:
            _retrying(lambda: rs.delete_cluster_snapshot(
                SnapshotIdentifier=snapshot_id, SnapshotClusterIdentifier=cluster_id
            ))
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
                return
            if _code_of(exc) != "InvalidClusterSnapshotState" or time.time() >= deadline:
                raise
        time.sleep(2)

CHECK = "resume-non-paused-cluster-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResumeCluster on an `available` cluster is rejected with InvalidClusterState "You can only
    resume a PAUSED Cluster" and the cluster stays available; once paused, the identical call
    returns it to available."""
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-resume-bad-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(
        **_cluster_params(
            rs, cluster_id, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
        )
    )
    _wait_for_cluster_available(rs, cluster_id, timeout_s=_budget_s(ctx, 660), ctx=ctx)

    code, message = _error(lambda: rs.resume_cluster(ClusterIdentifier=cluster_id))
    assert code == "InvalidClusterState", f"expected InvalidClusterState, got {code}"
    assert message == "You can only resume a PAUSED Cluster", message
    status = _cluster_status(rs, cluster_id)
    assert status == "available", (
        f"a rejected resume must not perturb cluster state, got {status!r}"
    )

    # Restore the precondition ResumeCluster actually requires, then demand the
    # identical call succeed, proving the earlier
    # rejection was a real state check rather than ResumeCluster being blanket-refused.
    # PauseCluster itself requires a recently-available backup (real AWS: "You can't
    # pause cluster ... because no recently available backup was found"), so a manual
    # snapshot must exist first — a freshly created cluster has no automated one yet.
    snapshot_id = ctx.unique_name("sim2real-behav-rs-resume-bad-snap-")
    ctx.on_cleanup(lambda: _delete_snapshot(rs, cluster_id, snapshot_id))
    rs.create_cluster_snapshot(ClusterIdentifier=cluster_id, SnapshotIdentifier=snapshot_id)
    _wait_for_snapshot_available(rs, snapshot_id, timeout_s=_budget_s(ctx, 240), ctx=ctx)

    _pause_when_active(rs, cluster_id, timeout_s=_budget_s(ctx, 180), ctx=ctx)
    _wait_for_cluster_status(rs, cluster_id, "paused", timeout_s=_budget_s(ctx, 300), ctx=ctx)

    _retrying(lambda: rs.resume_cluster(ClusterIdentifier=cluster_id))
    status = _wait_for_cluster_available(rs, cluster_id, timeout_s=_budget_s(ctx, 300), ctx=ctx)
    assert status == "available", (
        f"identical ResumeCluster call must succeed once actually paused, got {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
