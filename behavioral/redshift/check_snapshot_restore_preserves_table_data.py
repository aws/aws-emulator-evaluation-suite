"""snapshot-restore-preserves-table-data."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-restore-preserves-table-data"
GROUP = 'data-plane'
SERVICES = ['redshift']


# ===== helpers =====

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s, interval_s, what="condition", ctx=None):
    """Poll *probe* every *interval_s* until *done*, bounded by *timeout_s* and the check's
    remaining budget."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"waiting for {what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_NOT_FOUND_SNAPSHOT = ("ClusterSnapshotNotFound", "ClusterSnapshotNotFoundFault")
# Provisioning a cluster is minutes-scale (~317 s end to end). This check provisions TWO
# clusters and one snapshot in sequence, so each wait gets its own generous bounded deadline.
_CLUSTER_DEADLINE_S = 1200
_SNAPSHOT_DEADLINE_S = 1800
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420


def _node_type(rs, cluster_type="single-node"):
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
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
        DBName=DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    params.update(overrides)
    return params


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _describe_cluster(rs, cluster_id):
    resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S, ctx=None):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=2,
        what=f"cluster {cluster_id} to reach a terminal creation state",
        ctx=ctx,
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """SkipFinalClusterSnapshot=True so teardown leaves no billing snapshot behind."""
    deadline = time.monotonic() + 300
    while True:
        try:
            _retrying(lambda: rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_snapshot(rs, snapshot_id):
    """A manual snapshot is billed storage and is NOT removed by deleting its cluster, so it
    needs its own cleanup. A snapshot still 'creating' refuses deletion, hence the bounded
    retry loop."""
    deadline = time.monotonic() + 600
    while True:
        try:
            _retrying(lambda: rs.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id))
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
                return
            if _code_of(exc) != "InvalidClusterSnapshotState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _snapshot_status(rs, snapshot_id):
    try:
        resp = _retrying(lambda: rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_SNAPSHOT:
            return None
        raise
    snapshots = resp.get("Snapshots", [])
    return snapshots[0]["Status"] if snapshots else None


def _wait_for_snapshot_available(rs, snapshot_id, timeout_s=_SNAPSHOT_DEADLINE_S, ctx=None):
    status = _wait_until(
        lambda: _snapshot_status(rs, snapshot_id),
        lambda s: s in {"available", "failed", None},
        timeout_s=timeout_s,
        interval_s=2,
        what=f"snapshot {snapshot_id} to reach a terminal state",
        ctx=ctx,
    )
    assert status == "available", (
        f"snapshot {snapshot_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=1,
        what=f"statement {statement_id} to reach a terminal status",
        ctx=ctx,
    )


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s, ctx=ctx)
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} on {cluster_id} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql, ctx=None):
    statement_id = _run_sql(rsd, cluster_id, sql, ctx=ctx)
    return _retrying(lambda: rsd.get_statement_result(Id=statement_id))["Records"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A manual snapshot captures the cluster's table data: the restored cluster returns exactly
    the snapshotted rows, not a row written after the snapshot, and both clusters stay writable.

    Reference: https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    source_id = ctx.unique_name("sim2real-behav-rs-snapsrc-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, source_id))
    rs.create_cluster(**_cluster_params(rs, source_id))
    _wait_for_cluster_available(rs, source_id, ctx=ctx)

    table = "sim2real_behav_snapshot_rows"
    _run_sql(rsd, source_id, f"CREATE TABLE {table} (id INT, val VARCHAR(24))", ctx=ctx)
    _run_sql(
        rsd,
        source_id,
        f"INSERT INTO {table} VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')",
        ctx=ctx,
    )
    expected = [
        [{"longValue": 1}, {"stringValue": "alpha"}],
        [{"longValue": 2}, {"stringValue": "beta"}],
        [{"longValue": 3}, {"stringValue": "gamma"}],
    ]
    seeded = _select(rsd, source_id, f"SELECT id, val FROM {table} ORDER BY id", ctx=ctx)
    assert seeded == expected, f"setup did not seed the three rows: {seeded!r}"

    snapshot_id = ctx.unique_name("sim2real-behav-rs-snap-")
    ctx.on_cleanup(lambda: _delete_snapshot(rs, snapshot_id))
    created = _retrying(
        lambda: rs.create_cluster_snapshot(
            SnapshotIdentifier=snapshot_id,
            ClusterIdentifier=source_id,
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        )
    )["Snapshot"]
    assert created["SnapshotIdentifier"] == snapshot_id, created
    assert created["ClusterIdentifier"] == source_id, created
    assert created["SnapshotType"] == "manual", (
        f"an explicitly created snapshot must be SnapshotType 'manual', got {created.get('SnapshotType')!r}"
    )
    _wait_for_snapshot_available(rs, snapshot_id, ctx=ctx)

    # A row written AFTER the snapshot must NOT appear in the restore — this is what proves
    # the restore reads the snapshot rather than the live source cluster.
    _run_sql(rsd, source_id, f"INSERT INTO {table} VALUES (4, 'after-snapshot')", ctx=ctx)

    restored_id = ctx.unique_name("sim2real-behav-rs-snapdst-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, restored_id))
    restored = _retrying(
        lambda: rs.restore_from_cluster_snapshot(
            ClusterIdentifier=restored_id,
            SnapshotIdentifier=snapshot_id,
            PubliclyAccessible=False,
            AutomatedSnapshotRetentionPeriod=1,
        )
    )["Cluster"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    restored_arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{restored_id}"
    _retrying(
        lambda: rs.create_tags(
            ResourceName=restored_arn, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
        )
    )
    assert restored["ClusterIdentifier"] == restored_id, restored
    assert restored["DBName"] == DB_NAME, (
        f"the restored cluster must carry the snapshot's database name, got {restored.get('DBName')!r}"
    )
    assert restored["MasterUsername"] == MASTER_USERNAME, (
        f"the restored cluster must carry the snapshot's master user, got {restored.get('MasterUsername')!r}"
    )
    _wait_for_cluster_available(rs, restored_id, ctx=ctx)

    # The money assertion: the restored cluster's SQL engine holds the snapshotted rows.
    restored_rows = _select(rsd, restored_id, f"SELECT id, val FROM {table} ORDER BY id", ctx=ctx)
    assert restored_rows == expected, (
        "RestoreFromClusterSnapshot must reproduce the snapshotted table data exactly "
        f"(ordered); expected {expected!r}, got {restored_rows!r}"
    )

    # Point-in-time semantics: the post-snapshot row is absent from the restore...
    late = _select(
        rsd, restored_id, f"SELECT COUNT(*) FROM {table} WHERE val = 'after-snapshot'", ctx=ctx
    )
    assert late == [[{"longValue": 0}]], (
        "a row written after the snapshot was taken must not appear in the restored cluster, "
        f"got {late!r}"
    )
    # ...and still present on the source (the restore did not mutate the source).
    source_rows = _select(rsd, source_id, f"SELECT id, val FROM {table} ORDER BY id", ctx=ctx)
    assert source_rows == expected + [[{"longValue": 4}, {"stringValue": "after-snapshot"}]], (
        f"the source cluster must be untouched by the restore, got {source_rows!r}"
    )

    # Control: both clusters are independently writable afterwards.
    _run_sql(rsd, restored_id, f"INSERT INTO {table} VALUES (9, 'restored-write')", ctx=ctx)
    restored_after = _select(
        rsd, restored_id, f"SELECT COUNT(*) FROM {table}", ctx=ctx
    )
    assert restored_after == [[{"longValue": 4}]], (
        f"the restored cluster must accept new writes, got {restored_after!r}"
    )
    source_after = _select(rsd, source_id, f"SELECT COUNT(*) FROM {table}", ctx=ctx)
    assert source_after == [[{"longValue": 4}]], (
        f"a write to the restored cluster must not reach the source, got {source_after!r}"
    )
    final_source_status = _describe_cluster(rs, source_id)["ClusterStatus"]
    assert final_source_status == "available", (
        f"the source cluster must remain available after the restore and the write to the "
        f"restored cluster, got {final_source_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
