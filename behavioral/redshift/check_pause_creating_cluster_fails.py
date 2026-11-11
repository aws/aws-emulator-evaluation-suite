"""pause-creating-cluster-fails."""

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


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


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


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
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
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.time() >= deadline:
                raise
        time.sleep(2)

MSG_NOT_AVAILABLE = "You can only pause an ACTIVE Cluster"

CHECK = "pause-creating-cluster-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PauseCluster is only legal from `available`: pausing a `creating` cluster must be
    rejected, and the identical call must succeed once the cluster reaches `available` — the
    restore leg that rules out a target which rejects PauseCluster unconditionally."""
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-pause-bad-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(
        **_cluster_params(
            rs, cluster_id, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
        )
    )
    assert _cluster_status(rs, cluster_id) == "creating", (
        f"expected newly created cluster {cluster_id} to be 'creating'"
    )

    code, message = _refusal(lambda: rs.pause_cluster(ClusterIdentifier=cluster_id))
    assert code == "InvalidClusterState", f"expected InvalidClusterState, got {code}"
    assert message == MSG_NOT_AVAILABLE, f"expected {MSG_NOT_AVAILABLE!r}, got {message!r}"
    assert _cluster_status(rs, cluster_id) == "creating", "a rejected pause must not perturb cluster state"

    # PauseCluster keeps answering InvalidClusterState for a settling period (~80-90 s)
    # after ClusterStatus first reports 'available', so retry across a bounded window
    # well past that settle time rather than treating the first retry as final.
    became_available_at = time.time()
    _wait_for_cluster_available(rs, cluster_id, timeout_s=660)
    deadline = became_available_at + 300
    attempts = []
    while True:
        try:
            _retrying(lambda: rs.pause_cluster(ClusterIdentifier=cluster_id))
            code = "OK"
        except ClientError as exc:
            code = _code_of(exc)
        attempts.append((round(time.time() - became_available_at, 1), code))
        if code != "InvalidClusterState" or time.time() >= deadline:
            break
        time.sleep(2)
    assert code == "OK", (
        f"expected the identical PauseCluster to succeed once available, "
        f"attempts(elapsed_s, code)={attempts}"
    )
    status = _wait_for_cluster_status(
        rs, cluster_id, {"paused", "hardware-failure"},
        timeout_s=900, interval_s=15,
    )
    assert status == "paused", (
        f"expected cluster {cluster_id} to settle in paused, observed status {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
