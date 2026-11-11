"""snapshot-copy-ops-not-found-semantics."""

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


_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"


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


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _wait_for_cluster_available(rs, cluster_id, timeout_s=600, interval_s=15):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    deadline = time.time() + timeout_s
    while True:
        status = _cluster_status(rs, cluster_id)
        if status in terminal:
            assert status == "available", (
                f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
            )
            return
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for cluster {cluster_id} available")
        time.sleep(interval_s)


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


CHECK = "snapshot-copy-ops-not-found-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableSnapshotCopy, ModifySnapshotCopyRetentionPeriod and DisableSnapshotCopy take effect on
    an available cluster (destination region, retention 3, copy status cleared), and each answers
    ClusterNotFound for an unknown cluster identifier."""
    rs = ctx.client("redshift")

    cluster_id = ctx.unique_name("sim2real-behav-rs-copycl-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName="devdb",
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    _wait_for_cluster_available(rs, cluster_id)

    # Positive control: the same three ops against a cluster that exists.
    # DestinationRegion is a required cross-region-copy parameter (must differ from the
    # check's own us-west-2), not a resource region pin.
    enabled = rs.enable_snapshot_copy(
        ClusterIdentifier=cluster_id, DestinationRegion="us-east-2"
    )["Cluster"]
    copy_status = enabled.get("ClusterSnapshotCopyStatus") or {}
    assert copy_status.get("DestinationRegion") == "us-east-2", f"EnableSnapshotCopy did not take effect: {enabled}"

    modified = rs.modify_snapshot_copy_retention_period(
        ClusterIdentifier=cluster_id, RetentionPeriod=3
    )["Cluster"]
    modified_status = modified.get("ClusterSnapshotCopyStatus") or {}
    assert modified_status.get("RetentionPeriod") == 3, f"ModifySnapshotCopyRetentionPeriod did not take effect: {modified}"

    rs.disable_snapshot_copy(ClusterIdentifier=cluster_id)
    described = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    assert not described.get("ClusterSnapshotCopyStatus"), (
        f"expected snapshot copy disabled, still see {described.get('ClusterSnapshotCopyStatus')}"
    )

    # The negative: an unknown cluster identifier resolves to ClusterNotFound on all three,
    # never a different validation error and never silent success.
    missing = ctx.unique_name("sim2real-behav-rs-copycl-missing-")
    cases = {
        "EnableSnapshotCopy": lambda: rs.enable_snapshot_copy(
            ClusterIdentifier=missing, DestinationRegion="us-east-2"
        ),
        "DisableSnapshotCopy": lambda: rs.disable_snapshot_copy(ClusterIdentifier=missing),
        "ModifySnapshotCopyRetentionPeriod": lambda: rs.modify_snapshot_copy_retention_period(
            ClusterIdentifier=missing, RetentionPeriod=7
        ),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "ClusterNotFound")
    assert observed == expected, f"snapshot-copy contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
