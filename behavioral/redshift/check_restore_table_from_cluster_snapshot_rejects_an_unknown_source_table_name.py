"""restore-table-from-cluster-snapshot-rejects-an-unknown-source-table-name."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-table-from-cluster-snapshot-rejects-an-unknown-source-table-name"
GROUP = "snapshot-restore"
SERVICES = ["redshift"]

_ADMIN_USER = "sim2realadmin"
_DB_NAME = "sim2realdb"
_TABLE = "sim2real_restore_neighbour_source"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_TERMINAL_RESTORE = ("SUCCEEDED", "FAILED", "CANCELED")
_THROTTLE_CODES = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException")


def _api_code(exc) -> str:
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _api_message(exc) -> str:
    return exc.response["Error"]["Message"]


def _call_with_retry(fn, *, attempts: int = 6, backoff_s: float = 5.0):
    """Retries only a request-rate throttle; any other outcome propagates on the first try."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _api_code(exc) not in _THROTTLE_CODES:
                raise
            last_exc = exc
            time.sleep(backoff_s * (attempt + 1))
    raise last_exc


def _poll_until(probe, is_done, *, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if is_done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={observed!r}")
        time.sleep(interval_s)


def _cheapest_single_node_type(rs) -> str:
    seen = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        page = _call_with_retry(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for option in page.get("OrderableClusterOptions", []):
            if option.get("ClusterType") == "single-node":
                node_type = option.get("NodeType")
                if node_type and node_type not in seen:
                    seen.append(node_type)
        marker = page.get("Marker")
        if not marker:
            break
    for preferred in _NODE_TYPE_PREFERENCE:
        if preferred in seen:
            return preferred
    assert seen, "no single-node orderable cluster options in this region"
    return sorted(seen)[0]


def _describe_cluster(rs, cluster_id):
    try:
        clusters = _call_with_retry(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))["Clusters"]
    except ClientError as exc:
        if _api_code(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    return clusters[0] if clusters else None


def _wait_cluster_available(rs, cluster_id, *, timeout_s: float):
    def probe():
        cluster = _describe_cluster(rs, cluster_id)
        return cluster["ClusterStatus"] if cluster else None

    return _poll_until(probe, lambda s: s == "available", timeout_s=timeout_s, interval_s=15.0,
                        what=f"cluster {cluster_id} available")


def _delete_cluster_until_gone(rs, cluster_id, *, timeout_s: float = 600.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = _api_code(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    _poll_until(lambda: _describe_cluster(rs, cluster_id), lambda c: c is None,
                timeout_s=timeout_s, interval_s=10.0, what=f"cluster {cluster_id} to disappear")


def _delete_snapshot_until_gone(rs, cluster_id, snapshot_id, *, timeout_s: float = 300.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rs.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id, SnapshotClusterIdentifier=cluster_id)
            return
        except ClientError as exc:
            code = _api_code(exc)
            if code == "ClusterSnapshotNotFoundFault":
                return
            if code != "InvalidClusterSnapshotStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _wait_snapshot_available(rs, snapshot_id, *, timeout_s: float):
    def probe():
        page = _call_with_retry(lambda: rs.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id))
        snaps = page.get("Snapshots", [])
        return snaps[0]["Status"] if snaps else None

    return _poll_until(probe, lambda s: s == "available", timeout_s=timeout_s, interval_s=10.0,
                        what=f"snapshot {snapshot_id} available")


def _run_sql(rsd, cluster_id, sql, *, timeout_s: float):
    statement_id = _call_with_retry(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=_DB_NAME, DbUser=_ADMIN_USER, Sql=sql,
    ))["Id"]
    described = _poll_until(
        lambda: _call_with_retry(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s, interval_s=3.0, what=f"statement {statement_id} to reach a terminal status",
    )
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} did not FINISH: status={described['Status']!r} error={described.get('Error')!r}"
    )
    return statement_id


def _restore_table_once_cluster_settles(rs, *, timeout_s: float, **kwargs):
    """RestoreTableFromClusterSnapshot, retried on InvalidClusterState: a cluster that just
    finished a manual snapshot can briefly refuse it while post-snapshot bookkeeping settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rs.restore_table_from_cluster_snapshot(**kwargs)
        except ClientError as exc:
            if _api_code(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_table_restore(rs, request_id, *, timeout_s: float):
    def probe():
        page = _call_with_retry(lambda: rs.describe_table_restore_status(TableRestoreRequestId=request_id))
        entries = page.get("TableRestoreStatusDetails", [])
        return entries[0] if entries else None

    return _poll_until(probe, lambda e: e is not None and e.get("Status") in _TERMINAL_RESTORE,
                        timeout_s=timeout_s, interval_s=5.0,
                        what=f"table restore request {request_id} to reach a terminal status")


def _restores_naming(rs, cluster_id, source_table_name):
    """Every TableRestoreStatusDetails entry for this cluster whose SourceTableName matches."""
    entries, marker = [], None
    while True:
        kwargs = {"ClusterIdentifier": cluster_id, "MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        page = _call_with_retry(lambda: rs.describe_table_restore_status(**kwargs))
        entries.extend(
            e for e in page.get("TableRestoreStatusDetails", []) if e.get("SourceTableName") == source_table_name
        )
        marker = page.get("Marker")
        if not marker:
            break
    return entries


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreTableFromClusterSnapshot rejects a source table name absent from the snapshot with
    InvalidTableRestoreArgument naming it, queuing no restore request; the same snapshot's real
    table name restores successfully.

    Reference: https://repost.aws/knowledge-center/redshift-restore-snapshot-troubleshoot
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-rs-restneigh-")
    password = "Sim2realRestNeigh9!" + cluster_id[-6:]
    node_type = _cheapest_single_node_type(rs)
    _call_with_retry(lambda: rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=node_type,
        ClusterType="single-node",
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=password,
        DBName=_DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    ))
    ctx.on_cleanup(lambda: _delete_cluster_until_gone(rs, cluster_id))
    _wait_cluster_available(rs, cluster_id, timeout_s=900.0)

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_TABLE} (id INT NOT NULL)", timeout_s=120.0)
    _run_sql(rsd, cluster_id, f"INSERT INTO {_TABLE} (id) VALUES (1)", timeout_s=60.0)

    snapshot_id = ctx.unique_name("sim2real-rs-restneigh-snap-")
    _call_with_retry(lambda: rs.create_cluster_snapshot(
        ClusterIdentifier=cluster_id, SnapshotIdentifier=snapshot_id,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    ))
    ctx.on_cleanup(lambda: _delete_snapshot_until_gone(rs, cluster_id, snapshot_id))
    _wait_snapshot_available(rs, snapshot_id, timeout_s=900.0)

    missing_table = ctx.unique_name("sim2real_absent_table_").replace("-", "_")
    code = None
    message = None
    try:
        _restore_table_once_cluster_settles(
            rs, timeout_s=300.0,
            ClusterIdentifier=cluster_id,
            SnapshotIdentifier=snapshot_id,
            SourceDatabaseName=_DB_NAME,
            SourceSchemaName="public",
            SourceTableName=missing_table,
            TargetDatabaseName=_DB_NAME,
            TargetSchemaName="public",
            NewTableName=ctx.unique_name("sim2real_wont_exist_").replace("-", "_"),
        )
    except ClientError as exc:
        code = _api_code(exc)
        message = _api_message(exc)
    assert code == "InvalidTableRestoreArgument", (
        f"restoring an unknown source table name gave code {code!r} (message {message!r}), "
        "expected InvalidTableRestoreArgument"
    )
    assert message == (
        f'Source table "{missing_table}" doesn\'t exist in snapshot. Consider using: "{_TABLE}"'
    ), f"unexpected message for an unknown source table name: {message!r}"

    queued_for_missing = _restores_naming(rs, cluster_id, missing_table)
    assert queued_for_missing == [], (
        f"a refused restore must queue nothing, but {len(queued_for_missing)} request(s) name "
        f"{missing_table!r}: {queued_for_missing!r}"
    )

    restored_table = ctx.unique_name("sim2real_restored_neighbour_").replace("-", "_")
    restore_request = _restore_table_once_cluster_settles(
        rs, timeout_s=300.0,
        ClusterIdentifier=cluster_id,
        SnapshotIdentifier=snapshot_id,
        SourceDatabaseName=_DB_NAME,
        SourceSchemaName="public",
        SourceTableName=_TABLE,
        TargetDatabaseName=_DB_NAME,
        TargetSchemaName="public",
        NewTableName=restored_table,
    )["TableRestoreStatus"]
    settled = _wait_table_restore(rs, restore_request["TableRestoreRequestId"], timeout_s=900.0)
    assert settled["Status"] == "SUCCEEDED", (
        f"restoring the snapshot's real table name settled as {settled['Status']!r}: "
        f"{settled.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
