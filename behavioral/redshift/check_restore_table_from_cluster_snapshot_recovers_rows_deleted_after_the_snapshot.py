"""restore-table-from-cluster-snapshot-recovers-rows-deleted-after-the-snapshot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-table-from-cluster-snapshot-recovers-rows-deleted-after-the-snapshot"
GROUP = "snapshot-restore"
SERVICES = ["redshift"]

_ADMIN_USER = "sim2realadmin"
_DB_NAME = "sim2realdb"
_TABLE = "sim2real_restore_source"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_TERMINAL_RESTORE = ("SUCCEEDED", "FAILED", "CANCELED")
_THROTTLE_CODES = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException")


def _api_code(exc) -> str:
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


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

    status = _poll_until(probe, lambda s: s == "available", timeout_s=timeout_s, interval_s=15.0,
                          what=f"cluster {cluster_id} available")
    return status


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


def _ordered_column(rsd, statement_id):
    """Every row's first column, in the order GetStatementResult returned them, paginated."""
    values, token = [], None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        page = _call_with_retry(lambda: rsd.get_statement_result(**kwargs))
        for record in page.get("Records", []):
            field = record[0]
            values.append(None if field.get("isNull") else next(iter(field.values())))
        token = page.get("NextToken")
        if not token:
            break
    return values


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


def _wait_table_restore(rsd_status, request_id, *, timeout_s: float):
    def probe():
        page = _call_with_retry(lambda: rsd_status(TableRestoreRequestId=request_id))
        entries = page.get("TableRestoreStatusDetails", [])
        return entries[0] if entries else None

    entry = _poll_until(probe, lambda e: e is not None and e.get("Status") in _TERMINAL_RESTORE,
                         timeout_s=timeout_s, interval_s=5.0,
                         what=f"table restore request {request_id} to reach a terminal status")
    return entry


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """RestoreTableFromClusterSnapshot recovers, into a new table, the rows a snapshot held
    for a source table whose rows were deleted on the live cluster afterward.

    Reference: https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshot-restore-table-from-snapshot.html
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-rs-restore-")
    password = "Sim2realRestore9!" + cluster_id[-6:]
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

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_TABLE} (id INT NOT NULL, note VARCHAR(64) NOT NULL)", timeout_s=120.0)
    _run_sql(
        rsd, cluster_id,
        f"INSERT INTO {_TABLE} (id, note) VALUES (1, 'kept'), (2, 'deleted-after-snapshot'), "
        "(3, 'also-deleted-after-snapshot')",
        timeout_s=60.0,
    )
    before_ids = sorted(_ordered_column(rsd, _run_sql(
        rsd, cluster_id, f"SELECT id FROM {_TABLE} ORDER BY id", timeout_s=60.0,
    )))
    assert before_ids == [1, 2, 3], f"expected 3 seeded rows before the snapshot, read back {before_ids!r}"

    snapshot_id = ctx.unique_name("sim2real-rs-restore-snap-")
    _call_with_retry(lambda: rs.create_cluster_snapshot(
        ClusterIdentifier=cluster_id, SnapshotIdentifier=snapshot_id,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    ))
    ctx.on_cleanup(lambda: _delete_snapshot_until_gone(rs, cluster_id, snapshot_id))
    _wait_snapshot_available(rs, snapshot_id, timeout_s=900.0)

    _run_sql(rsd, cluster_id, f"DELETE FROM {_TABLE} WHERE id IN (2, 3)", timeout_s=60.0)
    after_delete_ids = sorted(_ordered_column(rsd, _run_sql(
        rsd, cluster_id, f"SELECT id FROM {_TABLE} ORDER BY id", timeout_s=60.0,
    )))
    assert after_delete_ids == [1], (
        f"expected only the kept row after the delete, read back {after_delete_ids!r}"
    )

    restored_table = ctx.unique_name("sim2real_restored_").replace("-", "_")
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
    request_id = restore_request["TableRestoreRequestId"]
    assert restore_request["Status"] in ("PENDING", "IN_PROGRESS"), (
        f"RestoreTableFromClusterSnapshot's own response reported Status="
        f"{restore_request['Status']!r}, expected a request still queued or running"
    )

    settled = _wait_table_restore(rs.describe_table_restore_status, request_id, timeout_s=900.0)
    assert settled["Status"] == "SUCCEEDED", (
        f"table restore request {request_id} settled as {settled['Status']!r}: {settled.get('Message')!r}"
    )

    restored_ids = sorted(_ordered_column(rsd, _run_sql(
        rsd, cluster_id, f"SELECT id FROM {restored_table} ORDER BY id", timeout_s=120.0,
    )))
    assert restored_ids == [1, 2, 3], (
        f"the restored table held {restored_ids!r}, expected the pre-delete rows [1, 2, 3]"
    )

    live_ids = sorted(_ordered_column(rsd, _run_sql(
        rsd, cluster_id, f"SELECT id FROM {_TABLE} ORDER BY id", timeout_s=60.0,
    )))
    assert live_ids == [1], (
        f"restoring into {restored_table!r} must not have changed the live table, which held "
        f"{live_ids!r}, expected [1]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
