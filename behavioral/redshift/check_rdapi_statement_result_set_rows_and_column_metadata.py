"""rdapi-statement-result-set-rows-and-column-metadata."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rdapi-statement-result-set-rows-and-column-metadata"
GROUP = "async-data-api"
SERVICES = ["redshift"]

_TABLE = "sim2real_rdapi_meta"
# One row fully populated and one with a NULL, so the Field union's isNull member is exercised
# alongside every other member the five column types produce.
_INSERT = (
    f"INSERT INTO {_TABLE} VALUES "
    "(1,'alpha',10.50,true,'2026-09-22 10:11:12'), "
    "(2,NULL,-3.25,false,'2026-01-02 03:04:05')"
)
# Every member
# choice here is a fidelity claim: DECIMAL and TIMESTAMP both come back as stringValue (not
# doubleValue, not an epoch), BOOLEAN as booleanValue, INT as longValue, and a SQL NULL as
# {"isNull": True} rather than an omitted or empty cell.
_EXPECTED_RECORDS = [
    [{"longValue": 1}, {"stringValue": "alpha"}, {"stringValue": "10.50"},
     {"booleanValue": True}, {"stringValue": "2026-09-22 10:11:12"}],
    [{"longValue": 2}, {"isNull": True}, {"stringValue": "-3.25"},
     {"booleanValue": False}, {"stringValue": "2026-01-02 03:04:05"}],
]
# Asserted whole rather than field-by-field: the engine reports the PostgreSQL
# type name (int4 / varchar / numeric / bool / timestamp), NOT NULL as nullable=0, VARCHAR(32)'s
# width in `precision` with `length` 0, and DECIMAL(9,2)'s scale.
_EXPECTED_COLUMN_METADATA = [
    {"isCaseSensitive": False, "isCurrency": False, "isSigned": True, "label": "id",
     "name": "id", "nullable": 0, "precision": 10, "scale": 0, "schemaName": "public",
     "tableName": _TABLE, "typeName": "int4", "length": 0},
    {"isCaseSensitive": True, "isCurrency": False, "isSigned": False, "label": "name",
     "name": "name", "nullable": 1, "precision": 32, "scale": 0, "schemaName": "public",
     "tableName": _TABLE, "typeName": "varchar", "length": 0},
    {"isCaseSensitive": False, "isCurrency": False, "isSigned": True, "label": "amt",
     "name": "amt", "nullable": 1, "precision": 9, "scale": 2, "schemaName": "public",
     "tableName": _TABLE, "typeName": "numeric", "length": 0},
    {"isCaseSensitive": False, "isCurrency": False, "isSigned": False, "label": "ok",
     "name": "ok", "nullable": 1, "precision": 1, "scale": 0, "schemaName": "public",
     "tableName": _TABLE, "typeName": "bool", "length": 0},
    {"isCaseSensitive": False, "isCurrency": False, "isSigned": False, "label": "ts",
     "name": "ts", "nullable": 1, "precision": 29, "scale": 6, "schemaName": "public",
     "tableName": _TABLE, "typeName": "timestamp", "length": 0},
]
_ORDER = {"SUBMITTED": 0, "PICKED": 1, "STARTED": 2, "FINISHED": 3}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SELECT through the Data API walks SUBMITTED -> PICKED -> STARTED -> FINISHED without going
    backwards, and its result carries the typed rows and the column metadata of the cluster's
    own catalog."""
    rs_data = ctx.client("redshift-data")
    cluster_id = _provision_cluster(ctx, "rdapi-meta")

    _run_sql(rs_data, cluster_id,
             f"CREATE TABLE {_TABLE} (id INT NOT NULL, name VARCHAR(32), amt DECIMAL(9,2), "
             "ok BOOLEAN, ts TIMESTAMP)")
    _run_sql(rs_data, cluster_id, _INSERT)

    sql = f"SELECT id, name, amt, ok, ts FROM {_TABLE} ORDER BY id"
    statement_id = _submit(rs_data, cluster_id, sql)

    seen: list[str] = []

    def _probe():
        described = _retrying(lambda: rs_data.describe_statement(Id=statement_id))
        if not seen or seen[-1] != described["Status"]:
            seen.append(described["Status"])
        return described

    final = _wait_until(_probe, lambda d: d["Status"] in _TERMINAL_STATEMENT,
                        timeout_s=_STATEMENT_DEADLINE_S, interval_s=1,
                        what="the SELECT to reach a terminal status")

    assert final["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the SELECT must FINISH, got {final['Status']!r} "
        f"error={final.get('Error')!r}")
    ranks = [_ORDER[s] for s in seen if s in _ORDER]
    assert ranks == sorted(ranks), (
        f"the statement lifecycle must advance monotonically; observed {seen!r}")
    assert set(seen) <= set(_ORDER), (
        f"observed a status outside the documented lifecycle: {seen!r}")
    assert final["HasResultSet"] is True, (
        f"a SELECT must report HasResultSet=True, got {final.get('HasResultSet')!r}")
    assert final["ResultRows"] == 2, (
        f"DescribeStatement must count the two rows the SELECT produced, got "
        f"{final.get('ResultRows')!r}")
    assert final["QueryString"] == sql, (
        f"DescribeStatement must echo the SQL verbatim, got {final.get('QueryString')!r}")
    assert final["UpdatedAt"] >= final["CreatedAt"], (
        f"UpdatedAt ({final['UpdatedAt']}) must not precede CreatedAt ({final['CreatedAt']})")

    records, page = _result(rs_data, statement_id)
    assert records == _EXPECTED_RECORDS, (
        f"{DATAPLANE_MARKER}: the fetched result set must carry the inserted rows in their "
        f"measured Field encodings; got {records!r} want {_EXPECTED_RECORDS!r}")
    assert page.get("TotalNumRows") == 2, (
        f"GetStatementResult must report TotalNumRows=2, got {page.get('TotalNumRows')!r}")
    assert page.get("NextToken") in (None, ""), (
        f"two rows fit in one page, so no continuation token is owed; got "
        f"{page.get('NextToken')!r}")
    assert page["ColumnMetadata"] == _EXPECTED_COLUMN_METADATA, (
        f"the column metadata must describe the five declared columns as the cluster catalog "
        f"does; got {page.get('ColumnMetadata')!r} want {_EXPECTED_COLUMN_METADATA!r}")


# ===== helpers =====
# The node type is derived from DescribeOrderableClusterOptions: dc2.large is not orderable in
# every region, so a pinned type can fail CreateCluster with InvalidParameterValue.

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded",
             "TooManyRequestsException", "SlowDown")
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# Cheapest first; whatever this region actually offers for a single node wins.
_SINGLE_NODE_PREFERENCE = ("ra3.large", "rg.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"  # noqa: S105 - throwaway cluster deleted in teardown
DB_NAME = "devdb"
# A single-node cluster reaches `available` in minutes and a first statement in seconds;
# _wait_until returns the instant its condition holds, and a target that never converges FAILS.
_CLUSTER_DEADLINE_S = 1200
_STATEMENT_DEADLINE_S = 420

# Prefixes a failure in which the API accepted the SQL but the engine never ran it to completion.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying ONLY on API throttling: a rate limit under parallel pool use is
    infrastructure noise, never a behavioral observation."""
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
    """Poll *probe* until *done*; never a bare sleep standing in for the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}")
        time.sleep(interval_s)


def _error(fn):
    """(code, HTTP status, message) of the ClientError *fn* raises.

    Raises when the call SUCCEEDS, so an accepted call is reported as such and not as something
    that reads like a naming difference."""
    try:
        fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"],
                exc.response["ResponseMetadata"]["HTTPStatusCode"],
                exc.response["Error"]["Message"])
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _node_type(rs):
    """Cheapest orderable SINGLE-NODE type in this region, fully paginated."""
    available, marker = [], None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") == "single-node" and opt.get("NodeType") not in available:
                available.append(opt["NodeType"])
        marker = resp.get("Marker")
        if not marker:
            break
    assert available, "no orderable single-node cluster options in this region"
    return next((n for n in _SINGLE_NODE_PREFERENCE if n in available), sorted(available)[0])


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _delete_cluster(rs, cluster_id):
    """Cost-leak teardown: SkipFinalClusterSnapshot so no snapshot blocks the delete and none is
    left billing. A cluster still `creating` refuses deletion, so retry inside a bounded window."""
    deadline = time.monotonic() + 600
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


def _provision_cluster(ctx, scenario, iam_roles=()):
    """A fresh single-node cluster, teardown registered BEFORE the create, waited to `available`.

    No ClusterSubnetGroupName and PubliclyAccessible=False: the Data API reaches the cluster over
    the AWS-managed path, and without Enhanced VPC Routing so does COPY's S3 read, so this check
    needs no VPC of its own and never touches one.
    """
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rdapi-")
    # A provisioned Redshift cluster is the most expensive leak in this service, so teardown is
    # registered before the identifier is used anywhere at all.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=MASTER_USERNAME,
        MasterUserPassword=MASTER_PASSWORD,
        ClusterType="single-node",
        DBName=DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,  # RA3 refuses 0
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    if iam_roles:
        # Attached AT CREATE rather than through ModifyClusterIamRoles: the association is then
        # complete when the cluster is, and the ~105 s provisioning wait doubles as the IAM
        # propagation window a COPY needs.
        params["IamRoles"] = list(iam_roles)
    deadline = time.monotonic() + 180
    while True:
        try:
            _retrying(lambda: rs.create_cluster(**params))
            break
        except ClientError as exc:
            # A role created seconds ago is not yet visible to the Redshift control plane, which
            # rejects the association outright rather than converging: the one place a create
            # legitimately retries on a 4xx.
            if _code_of(exc) not in ("InvalidIamRoleFault", "AccessDenied") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in ("available", "incompatible-network", "incompatible-parameters",
                        "incompatible-hsm", "insufficient-capacity", "hardware-failure", None),
        timeout_s=_CLUSTER_DEADLINE_S, interval_s=10,
        what=f"cluster {cluster_id} to reach a terminal creation state")
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'")
    return cluster_id


def _submit(rsd, cluster_id, sql, **extra):
    return _retrying(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql,
        **extra))["Id"]


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    """Poll DescribeStatement to a TERMINAL status; SUBMITTED/PICKED/STARTED are transient."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s, interval_s=3,
        what=f"statement {statement_id} to reach a terminal status")


def _describe_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, **extra):
    """Submit *sql*, wait for terminal, return the DescribeStatement WITHOUT asserting on it."""
    return _wait_statement(rsd, _submit(rsd, cluster_id, sql, **extra), timeout_s=timeout_s)


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, **extra):
    """Submit *sql*, wait for terminal, assert it FINISHED. -> the statement id."""
    statement_id = _submit(rsd, cluster_id, sql, **extra)
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}")
    return statement_id


def _result(rsd, statement_id):
    """(all records, the last page) of GetStatementResult, token-paginated."""
    records, token, page = [], None, None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        page = _retrying(lambda: rsd.get_statement_result(**kwargs))
        records.extend(page.get("Records", []))
        token = page.get("NextToken")
        if not token:
            return records, page


def _select(rsd, cluster_id, sql):
    """Every row of a SELECT that must FINISH."""
    return _result(rsd, _run_sql(rsd, cluster_id, sql))[0]


def _cell(record, i):
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
