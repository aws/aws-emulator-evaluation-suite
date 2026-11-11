"""data-api-batch-partial-failure-rolls-back-whole-batch."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-batch-partial-failure-rolls-back-whole-batch"
GROUP = 'overly-permissive'
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


def _wait_until(probe, done, timeout_s, interval_s, what="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_CLUSTER_DEADLINE_S = 1200
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
        MasterUserPassword=ADMIN_PASSWORD,
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


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S):
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
        interval_s=15,
        what=f"cluster {cluster_id} to reach a terminal creation state",
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
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} did not FINISH: status={described['Status']!r} error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql):
    return _retrying(lambda: rsd.get_statement_result(Id=_run_sql(rsd, cluster_id, sql)))["Records"]


def _run_sql_expect_fail(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FAILED", (
        f"SQL {sql!r} was expected to fail, got status={described['Status']!r}"
    )
    return described


def _run_batch(rsd, cluster_id, sqls):
    batch_id = _retrying(
        lambda: rsd.batch_execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sqls=sqls
        )
    )["Id"]
    return batch_id, _wait_statement(rsd, batch_id)


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement is one transaction: when the middle of three statements fails, the
    batch reports FAILED and the first statement's write is rolled back, while the corrected
    batch commits all three rows."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-behav-rs-batchfail-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_batch_atomic"
    _run_sql(rsd, cluster_id, f"CREATE TABLE {table} (id INT, val VARCHAR(16))")
    _run_sql(rsd, cluster_id, f"INSERT INTO {table} VALUES (1, 'kept')")
    baseline = _select(rsd, cluster_id, f"SELECT id, val FROM {table} ORDER BY id")
    assert baseline == [[{"longValue": 1}, {"stringValue": "kept"}]], (
        f"setup did not leave exactly the one seeded row: {baseline!r}"
    )

    bad_sqls = [
        f"INSERT INTO {table} VALUES (2, 'rolled-back')",
        # The one broken thing: no_such_column does not exist.
        f"INSERT INTO {table} SELECT no_such_column, 'boom' FROM {table}",
        f"INSERT INTO {table} VALUES (3, 'never-ran')",
    ]
    batch_id, described = _run_batch(rsd, cluster_id, bad_sqls)
    assert batch_id, "BatchExecuteStatement must accept the batch and return an Id"
    assert described["Status"] == "FAILED", (
        f"a batch containing a failing statement must reach FAILED, got {described.get('Status')!r}"
    )

    subs = described["SubStatements"]
    assert len(subs) == len(bad_sqls), (
        f"expected {len(bad_sqls)} SubStatements, got {len(subs)}"
    )
    assert subs[0]["Status"] == "FINISHED", (
        f"the first sub-statement ran before the failure, expected FINISHED, got {subs[0].get('Status')!r}"
    )
    assert subs[1]["Status"] == "FAILED", (
        f"the broken sub-statement must be FAILED, got {subs[1].get('Status')!r}"
    )
    assert subs[1].get("Error") and "no_such_column" in subs[1]["Error"], (
        f"the failing sub-statement's Error must name the offending column, got {subs[1].get('Error')!r}"
    )
    assert subs[2]["Status"] != "FINISHED", (
        "statements after the failure must not run to completion, got "
        f"{subs[2].get('Status')!r} for {subs[2].get('QueryString')!r}"
    )

    # Effect absent — the whole point: the FINISHED sub-statement's write is rolled back,
    # so the table is byte-for-byte what it was before the batch.
    after = _select(rsd, cluster_id, f"SELECT id, val FROM {table} ORDER BY id")
    assert after == baseline, (
        "a failed batch runs as one transaction and must roll ALL of it back; expected "
        f"{baseline!r}, got {after!r} (a 'rolled-back' or 'never-ran' row means the target "
        "executed the array as independent statements)"
    )

    # Control: the same batch with the middle statement corrected commits all of it.
    good_sqls = [
        f"INSERT INTO {table} VALUES (2, 'committed')",
        f"INSERT INTO {table} SELECT 4, 'derived' FROM {table} WHERE id = 1",
        f"INSERT INTO {table} VALUES (3, 'committed')",
    ]
    _, control = _run_batch(rsd, cluster_id, good_sqls)
    assert control["Status"] == "FINISHED", (
        f"the corrected batch must FINISH, got {control.get('Status')!r} error={control.get('Error')!r}"
    )
    final = _select(rsd, cluster_id, f"SELECT id, val FROM {table} ORDER BY id")
    assert final == [
        [{"longValue": 1}, {"stringValue": "kept"}],
        [{"longValue": 2}, {"stringValue": "committed"}],
        [{"longValue": 3}, {"stringValue": "committed"}],
        [{"longValue": 4}, {"stringValue": "derived"}],
    ], f"the corrected batch must commit every statement, got {final!r}"

    _run_sql(rsd, cluster_id, f"DROP TABLE {table}")

    # Delete proven gone: an independent read against the dropped table must fail,
    # naming the now-absent table.
    dropped = _run_sql_expect_fail(rsd, cluster_id, f"SELECT * FROM {table}")
    assert dropped.get("Error") and table in dropped["Error"], (
        f"a read of the dropped table must fail naming it, got {dropped.get('Error')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
