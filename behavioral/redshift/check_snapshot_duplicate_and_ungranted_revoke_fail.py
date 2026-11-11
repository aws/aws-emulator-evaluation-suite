"""snapshot-duplicate-and-ungranted-revoke-fail."""

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
    """Call *fn*, retrying only on API throttling, which is not a behavioral observation."""
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
# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _deadline(teardown_deadline: dict) -> float:
    """The run's teardown deadline, started by the first teardown that asks for it."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S)


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


def _wait_for_cluster_gone(rs, cluster_id, deadline):
    """Poll DescribeClusters every 2 s until it answers ClusterNotFound; raise at *deadline*."""
    while True:
        try:
            clusters = rs.describe_clusters(ClusterIdentifier=cluster_id).get("Clusters", [])
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            raise
        if time.monotonic() >= deadline:
            status = clusters[0].get("ClusterStatus") if clusters else None
            raise TimeoutError(f"cluster {cluster_id} still listed ({status!r}) at the teardown "
                               f"deadline")
        time.sleep(2)


def _delete_cluster(rs, cluster_id, teardown_deadline):
    """Teardown: a cluster still 'creating' may refuse deletion, so that is retried, and the delete
    is asynchronous, so the wait for ClusterNotFound follows, both to the run's deadline."""
    deadline = _deadline(teardown_deadline)
    while True:
        try:
            _retrying(lambda: rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_for_cluster_gone(rs, cluster_id, deadline)


_NOT_FOUND_SNAPSHOT = ("ClusterSnapshotNotFound", "ClusterSnapshotNotFoundFault")


def _delete_snapshot(rs, snapshot_id, teardown_deadline):
    """Teardown: a manual snapshot outlives its cluster, so revoke any grant left on it, delete it,
    retrying InvalidClusterSnapshotState (still creating) every 2 s, and poll every 2 s until
    ClusterSnapshotNotFound, which a snapshot never created also answers."""
    deadline = _deadline(teardown_deadline)
    try:
        granted = _restore_accounts(rs, snapshot_id)
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
            return
        raise
    for account in granted:
        rs.revoke_snapshot_access(SnapshotIdentifier=snapshot_id, AccountWithRestoreAccess=account)
    while True:
        try:
            rs.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id)
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
                return
            if _code_of(exc) != "InvalidClusterSnapshotState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"snapshot {snapshot_id} still listed at the teardown deadline")
        time.sleep(2)


def _snapshot_status(rs, snapshot_id, cluster_id=None):
    kwargs = {"SnapshotIdentifier": snapshot_id} if snapshot_id else {"ClusterIdentifier": cluster_id}
    try:
        resp = _retrying(lambda: rs.describe_cluster_snapshots(**kwargs))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_SNAPSHOT + _NOT_FOUND_CLUSTER:
            return None
        raise
    snaps = resp.get("Snapshots", [])
    return snaps[0]["Status"] if snaps else None


def _wait_for_snapshot_status(rs, snapshot_id, target_statuses, cluster_id=None, timeout_s=420, interval_s=15):
    targets = {target_statuses} if isinstance(target_statuses, str) else set(target_statuses)
    return _wait_until(
        lambda: _snapshot_status(rs, snapshot_id, cluster_id=cluster_id),
        lambda s: s in targets,
        timeout_s=timeout_s,
        interval_s=interval_s,
        what=f"snapshot {snapshot_id} status in {sorted(str(t) for t in targets)}",
    )


def _describe_snapshot(rs, snapshot_id):
    resp = _retrying(lambda: rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id))
    snaps = resp.get("Snapshots", [])
    return snaps[0] if snaps else None


def _restore_accounts(rs, snapshot_id):
    snap = _describe_snapshot(rs, snapshot_id)
    accounts = snap.get("AccountsWithRestoreAccess", []) if snap else []
    return [a.get("AccountId") for a in accounts]


CHECK = "snapshot-duplicate-and-ungranted-revoke-fail"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

SECOND_ACCOUNT = "444455556666"
GRANTED_ACCOUNT = "555566667777"

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a snapshot id fails with ClusterSnapshotAlreadyExists without replacing it; revoking
    an ungranted account fails with AccessToSnapshotDenied (not a not-found) leaving grants intact,
    while revoking a granted account succeeds.
    """
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rs-snapdup-")
    # One deadline for every teardown of the run, started by the first one that runs.
    teardown_deadline: dict = {}
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id, teardown_deadline))
    rs.create_cluster(**_cluster_params(
        rs, cluster_id, Tags=[{"Key": "sim2real", "Value": "snapdup"}]
    ))
    _wait_for_cluster_available(rs, cluster_id, timeout_s=420)

    snapshot_id = ctx.unique_name("sim2real-behav-rs-snapdup-s-")
    ctx.on_cleanup(lambda: _delete_snapshot(rs, snapshot_id, teardown_deadline))
    rs.create_cluster_snapshot(
        SnapshotIdentifier=snapshot_id,
        ClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "snapdup"}],
    )
    _wait_for_snapshot_status(rs, snapshot_id, "available", cluster_id=cluster_id, timeout_s=300)
    original_create_time = _describe_snapshot(rs, snapshot_id)["SnapshotCreateTime"]

    dup_code, dup_message = _error(lambda: rs.create_cluster_snapshot(
        SnapshotIdentifier=snapshot_id, ClusterIdentifier=cluster_id
    ))
    assert dup_code == "ClusterSnapshotAlreadyExists", (
        f"expected ClusterSnapshotAlreadyExists for a reused snapshot id, got {dup_code!r}"
    )
    assert dup_message == (
        f"Cannot create the snapshot because a snapshot with the identifier {snapshot_id} already exists."
    ), dup_message
    after_dup = _describe_snapshot(rs, snapshot_id)
    assert after_dup["SnapshotCreateTime"] == original_create_time, (
        f"the rejected duplicate create must not replace the snapshot: "
        f"expected SnapshotCreateTime={original_create_time!r}, got {after_dup['SnapshotCreateTime']!r}"
    )

    # Positive control: a real grant, so the denied revoke below is specific to the ungranted account.
    rs.authorize_snapshot_access(
        SnapshotIdentifier=snapshot_id, AccountWithRestoreAccess=GRANTED_ACCOUNT
    )
    granted = _restore_accounts(rs, snapshot_id)
    assert GRANTED_ACCOUNT in granted, f"expected {GRANTED_ACCOUNT} to hold restore access, got {granted}"

    revoke_code, revoke_message = _error(lambda: rs.revoke_snapshot_access(
        SnapshotIdentifier=snapshot_id, AccountWithRestoreAccess=SECOND_ACCOUNT
    ))
    assert revoke_code == "AccessToSnapshotDenied", (
        f"expected AccessToSnapshotDenied for revoking an ungranted account, got {revoke_code!r}"
    )
    assert revoke_message == (
        f"The account {SECOND_ACCOUNT} is not authorized to access the snapshot {snapshot_id}"
    ), revoke_message
    unaffected = _restore_accounts(rs, snapshot_id)
    assert SECOND_ACCOUNT not in unaffected, (
        f"the denied revoke must not add {SECOND_ACCOUNT} to restore access, got {unaffected}"
    )
    assert GRANTED_ACCOUNT in unaffected, (
        f"the denied revoke of {SECOND_ACCOUNT} must not disturb {GRANTED_ACCOUNT}'s grant, got {unaffected}"
    )

    # The identical revoke for the granted account succeeds.
    rs.revoke_snapshot_access(
        SnapshotIdentifier=snapshot_id, AccountWithRestoreAccess=GRANTED_ACCOUNT
    )
    final_accounts = _restore_accounts(rs, snapshot_id)
    assert GRANTED_ACCOUNT not in final_accounts, (
        f"expected {GRANTED_ACCOUNT}'s restore access to be revoked, got {final_accounts}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
