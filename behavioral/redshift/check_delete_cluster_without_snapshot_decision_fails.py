"""delete-cluster-without-snapshot-decision-fails."""

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

MSG_NO_DECISION = "FinalClusterSnapshotIdentifier is required unless SkipFinalClusterSnapshot is specified."
MSG_NOT_FOUND = "Cluster {cluster_id} not found."

CHECK = "delete-cluster-without-snapshot-decision-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster without a final-snapshot decision is refused (SkipFinalClusterSnapshot
    defaults to false, which requires FinalClusterSnapshotIdentifier), and the identical call
    succeeds once SkipFinalClusterSnapshot=True is supplied."""
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-delreq-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id, timeout_s=480)

    code, message = _refusal(lambda: rs.delete_cluster(ClusterIdentifier=cluster_id))
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    assert message == MSG_NO_DECISION, f"expected {MSG_NO_DECISION!r}, got {message!r}"
    assert _cluster_status(rs, cluster_id) == "available", "the rejected delete must not have taken effect"

    # the identical call with a snapshot decision must succeed: its own response reports the
    # cluster deleting, and the terminal outcome (the cluster is gone) is graded below.
    deleted = rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)["Cluster"]
    assert deleted["ClusterIdentifier"] == cluster_id, f"unexpected delete response {deleted!r}"
    assert deleted["ClusterStatus"] == "deleting", (
        f"the identical call with a snapshot decision must succeed: expected deleting, got {deleted['ClusterStatus']}"
    )

    gone = _wait_for_cluster_gone(rs, cluster_id, timeout_s=300)
    assert gone is None, f"cluster still reachable after the decided delete, status={gone}"

    code, message = _refusal(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    assert code == "ClusterNotFound", f"expected ClusterNotFound after deletion, got {code}"
    expected = MSG_NOT_FOUND.format(cluster_id=cluster_id)
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
