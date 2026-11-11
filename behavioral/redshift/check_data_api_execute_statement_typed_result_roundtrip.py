"""data-api-execute-statement-typed-result-roundtrip."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-execute-statement-typed-result-roundtrip"
GROUP = 'data-plane'
SERVICES = ['redshift']


# ===== helpers =====
# The Data API helpers below are this check's own.

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


def _wait_until(probe, done, timeout_s, interval_s, what="condition"):
    """Poll *probe* until *done*; never a bare sleep as the assertion."""
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


MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# The harness's per-check budget for this suite: the provisioning wait ends only where the
# runner would stop the check anyway, and returns the instant the cluster is available.
_SUITE_BUDGET_S = 1800


#: A fixed single-node type rather than a DescribeOrderableClusterOptions lookup: the node-type
#: catalog is not this check's claim.
NODE_TYPE = "ra3.large"


def _cluster_params(rs, cluster_id, **overrides):
    """Cheapest shape that still proves the invariant: ONE dc2.large/ra3.large node, not
    publicly accessible (the Data API reaches the cluster over the AWS-managed path, so no
    security group and no public endpoint are needed), 1-day snapshot retention."""
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=NODE_TYPE,
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


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_SUITE_BUDGET_S):
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


def _delete_cluster(rs, cluster_id, wait_gone=False):
    """Cost-leak teardown. SkipFinalClusterSnapshot=True so no snapshot is left billing;
    a cluster still 'creating' can refuse deletion, so retry inside a bounded window."""
    deadline = time.monotonic() + 300
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    if wait_gone:
        gone_deadline = time.monotonic() + 900
        while time.monotonic() < gone_deadline:
            if _cluster_status(rs, cluster_id) is None:
                return
            time.sleep(20)


_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# The first Data API statement against a freshly-available cluster includes connection
# establishment, so the statement deadline is deliberately larger than a warm query's.
_STATEMENT_DEADLINE_S = 420


def _submit(rsd, cluster_id, sql, **kwargs):
    """ExecuteStatement -> statement Id (the Data API is async: this returns immediately)."""
    resp = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=MASTER_USERNAME,
            Sql=sql,
            **kwargs,
        )
    )
    return resp


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    """Poll DescribeStatement to a TERMINAL status (SUBMITTED/PICKED/STARTED are transient)."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the DescribeStatement."""
    statement_id = _submit(rsd, cluster_id, sql)["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"DATAPLANE_UNIMPLEMENTED: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return described


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SQL submitted through the Redshift Data API executes on the cluster: the statement reaches
    FINISHED with result metadata, and ColumnMetadata and each value's Field union member carry
    the SQL type; a table created, written, read and dropped through the API ends gone."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-behav-rs-dapi-")
    # Registered BEFORE the identifier is used anywhere: a provisioned Redshift cluster is
    # the single most expensive leak in this service.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id)

    # A table lifecycle through the Data API: create, write two rows, read exactly those back.
    table = "s2r_dapi_" + ctx.unique_name("")
    _run_sql(rsd, cluster_id, f"CREATE TABLE {table} (id INT NOT NULL, label VARCHAR(16))")
    _run_sql(rsd, cluster_id, f"INSERT INTO {table} (id, label) VALUES (1, 'alpha'), (2, 'beta')")
    rows_id = _run_sql(rsd, cluster_id, f"SELECT id, label FROM {table} ORDER BY id")["Id"]
    rows = _retrying(lambda: rsd.get_statement_result(Id=rows_id))["Records"]
    assert rows == [
        [{"longValue": 1}, {"stringValue": "alpha"}],
        [{"longValue": 2}, {"stringValue": "beta"}],
    ], f"the rows read back from {table} are not the two inserted: {rows!r}"

    submitted = _submit(
        rsd,
        cluster_id,
        # The fourth column is a SECOND, differently-declared VARCHAR: it is what makes the
        # width assertions below falsifiable, since an emulator that reports one constant width
        # for every varchar cannot satisfy both 32 and 8.
        "SELECT 1 AS n, CAST('sim2real' AS VARCHAR(32)) AS s, CAST(NULL AS INTEGER) AS z, "
        "CAST('s2r' AS VARCHAR(8)) AS w",
        StatementName="sim2real-behav-typed-select",
    )
    statement_id = submitted["Id"]
    assert statement_id, f"ExecuteStatement returned no Id: {submitted}"
    assert submitted["ClusterIdentifier"] == cluster_id, submitted
    assert submitted["Database"] == DB_NAME, submitted
    assert submitted.get("CreatedAt") is not None, "ExecuteStatement must report CreatedAt"

    described = _wait_statement(rsd, statement_id)
    assert described["Status"] == "FINISHED", (
        f"statement did not FINISH: {described.get('Status')!r} error={described.get('Error')!r}"
    )
    assert described["HasResultSet"] is True, (
        f"a SELECT must report HasResultSet=True, got {described.get('HasResultSet')!r}"
    )
    assert described["ResultRows"] == 1, f"expected ResultRows=1, got {described.get('ResultRows')!r}"
    assert described.get("RedshiftPid", 0) > 0, (
        f"a statement that ran on the backend must report a RedshiftPid, got {described.get('RedshiftPid')!r}"
    )
    assert described.get("Duration", 0) > 0, (
        f"a FINISHED statement must report a positive Duration, got {described.get('Duration')!r}"
    )
    assert described["QueryString"].startswith("SELECT 1 AS n"), described["QueryString"]
    assert described.get("Error") in (None, ""), (
        f"a FINISHED statement must carry no Error, got {described.get('Error')!r}"
    )

    result = _retrying(lambda: rsd.get_statement_result(Id=statement_id))
    assert result["TotalNumRows"] == 1, f"expected TotalNumRows=1, got {result.get('TotalNumRows')!r}"

    columns = result["ColumnMetadata"]
    assert [c["name"] for c in columns] == ["n", "s", "z", "w"], (
        f"column order/names must match the SELECT list, got {[c.get('name') for c in columns]}"
    )
    assert columns[0]["typeName"] == "int4", (
        f"integer literal column must be typed int4, got {columns[0].get('typeName')!r}"
    )
    assert columns[1]["typeName"] == "varchar", (
        f"VARCHAR cast must report typeName 'varchar', got {columns[1].get('typeName')!r}"
    )
    assert columns[3]["typeName"] == "varchar", (
        f"VARCHAR cast must report typeName 'varchar', got {columns[3].get('typeName')!r}"
    )
    # The declared character width is carried by `precision`, NOT by `length`: `length` is 0 for
    # every column Redshift returns, while precision tracks the declared width exactly (32 here,
    # 8 for w, 65535 for an unbounded varchar, 10 for int4).
    assert columns[1]["precision"] == 32, (
        f"VARCHAR(32) must report its declared width 32 in precision, got "
        f"{columns[1].get('precision')!r}"
    )
    assert columns[3]["precision"] == 8, (
        f"VARCHAR(8) must report its declared width 8 in precision, got "
        f"{columns[3].get('precision')!r}"
    )
    assert [c["length"] for c in columns] == [0, 0, 0, 0], (
        "real Redshift leaves ColumnMetadata.length at 0 for every column; an emulator that puts "
        f"the width there instead of in precision is a fidelity gap, got {[c.get('length') for c in columns]}"
    )
    assert columns[2]["nullable"] == 1, (
        f"a NULL-cast column must be reported nullable, got {columns[2].get('nullable')!r}"
    )
    # The varchar columns are case-sensitive and unsigned, the integer is signed: the flags are
    # per-type facts, not constants.
    assert columns[0]["isSigned"] is True, columns[0]
    assert columns[1]["isSigned"] is False and columns[1]["isCaseSensitive"] is True, columns[1]
    assert columns[0]["isCaseSensitive"] is False, columns[0]

    records = result["Records"]
    assert len(records) == 1, f"expected exactly one record, got {len(records)}"
    row = records[0]
    # Field is a Smithy UNION: the KEY is the type discriminator, not decoration.
    assert row[0] == {"longValue": 1}, f"integer cell must be a longValue union member, got {row[0]!r}"
    assert row[1] == {"stringValue": "sim2real"}, (
        f"varchar cell must be a stringValue union member, got {row[1]!r}"
    )
    assert row[2] == {"isNull": True}, (
        f"a SQL NULL must be the isNull union member, not an empty string, got {row[2]!r}"
    )
    assert row[3] == {"stringValue": "s2r"}, (
        f"the second varchar cell must be a stringValue union member, got {row[3]!r}"
    )

    listed = _retrying(lambda: rsd.list_statements(ClusterIdentifier=cluster_id, MaxResults=20))
    matching = [s for s in listed["Statements"] if s["Id"] == statement_id]
    assert len(matching) == 1, (
        f"ListStatements must report the executed statement exactly once, got {len(matching)}"
    )
    assert matching[0]["Status"] == "FINISHED", matching[0]
    assert matching[0]["StatementName"] == "sim2real-behav-typed-select", matching[0]

    # Drop the table, then prove it gone: a read of it fails naming it, and it is unlisted.
    _run_sql(rsd, cluster_id, f"DROP TABLE {table}")
    dead_id = _submit(rsd, cluster_id, f"SELECT id FROM {table}")["Id"]
    dead = _wait_statement(rsd, dead_id)
    assert dead["Status"] == "FAILED", (
        f"a SELECT from the dropped table ended {dead['Status']!r}, expected FAILED"
    )
    assert table in (dead.get("Error") or ""), (
        f"the failed SELECT's Error does not name the dropped table: {dead.get('Error')!r}"
    )
    listed_tables = [
        t.get("name")
        for page in rsd.get_paginator("list_tables").paginate(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, TablePattern=table
        )
        for t in page["Tables"]
    ]
    assert table not in listed_tables, f"ListTables still lists the dropped table: {listed_tables!r}"

    # Control: the cluster is still healthy after the data-plane work.
    final_status = _cluster_status(rs, cluster_id)
    assert final_status == "available", (
        f"cluster {cluster_id} expected to remain 'available' after Data API work, got {final_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
