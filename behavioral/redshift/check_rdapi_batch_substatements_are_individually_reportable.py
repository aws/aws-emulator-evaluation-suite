"""rdapi-batch-substatements-are-individually-reportable."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rdapi-batch-substatements-are-individually-reportable"
GROUP = "async-data-api"
SERVICES = ["redshift"]

_TABLE = "sim2real_rdapi_batch"
_SQLS = [
    f"CREATE TABLE {_TABLE} (k INT, v VARCHAR(8))",
    f"INSERT INTO {_TABLE} VALUES (1,'one'),(2,'two')",
    f"SELECT k, v FROM {_TABLE} ORDER BY k",
    f"SELECT count(*) FROM {_TABLE}",
]
# Per sub-statement and in order: whether it owns a result set, and the row count its OWN
# record reports.
_EXPECTED_HAS_RESULT_SET = [False, False, True, True]
_EXPECTED_SUB_RESULT_ROWS = [0, 2, 2, 1]
_PARENT_REJECTION = "BatchExecuteStatement result can only be retrieved with sub-statement id."
_NO_RESULT_MESSAGE = "Query does not have result. Please check query status with DescribeStatement."


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A batch is a parent id over four independently reportable sub-statements: each carries its
    own `<parent>:<n>` id, SQL, row count and result set, while a result read of the parent, or of
    a sub-statement that produced no rows, is refused."""
    rs_data = ctx.client("redshift-data")
    cluster_id = _provision_cluster(ctx, "rdapi-batch")

    parent_id = _retrying(lambda: rs_data.batch_execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME,
        Sqls=_SQLS))["Id"]
    parent = _wait_statement(rs_data, parent_id)

    assert parent["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the batch must FINISH, got {parent['Status']!r} "
        f"error={parent.get('Error')!r}")
    assert parent["HasResultSet"] is True, (
        f"a batch containing SELECTs must report HasResultSet=True on the parent, got "
        f"{parent.get('HasResultSet')!r}")
    assert parent["ResultRows"] == -1, (
        f"the parent aggregates no row count of its own and must report -1, got "
        f"{parent.get('ResultRows')!r}")

    subs = parent.get("SubStatements")
    assert isinstance(subs, list) and len(subs) == len(_SQLS), (
        f"DescribeStatement must report one sub-statement per submitted SQL "
        f"({len(_SQLS)}); got {subs!r}")
    for n, (sub, sql) in enumerate(zip(subs, _SQLS), start=1):
        assert sub["Id"] == f"{parent_id}:{n}", (
            f"sub-statement {n} must be addressable as '<parent>:{n}'; got {sub['Id']!r}")
        assert sub["Status"] == "FINISHED", (
            f"sub-statement {n} must FINISH, got {sub['Status']!r} error={sub.get('Error')!r}")
        assert sub["QueryString"] == sql, (
            f"sub-statement {n} must echo its own SQL; got {sub.get('QueryString')!r}")
        assert sub["HasResultSet"] is _EXPECTED_HAS_RESULT_SET[n - 1], (
            f"sub-statement {n} HasResultSet must be {_EXPECTED_HAS_RESULT_SET[n - 1]!r}; got "
            f"{sub.get('HasResultSet')!r}")
        assert sub["ResultRows"] == _EXPECTED_SUB_RESULT_ROWS[n - 1], (
            f"sub-statement {n} must report {_EXPECTED_SUB_RESULT_ROWS[n - 1]} rows in its own "
            f"record; got {sub.get('ResultRows')!r}")

    # The parent id is not a readable handle, and neither is a sub-statement with no result set.
    code, status, message = _error(lambda: rs_data.get_statement_result(Id=parent_id))
    assert code == "ValidationException", (
        f"reading a batch's result from the PARENT id must be rejected ValidationException, got "
        f"{code!r}")
    assert status == 400, f"expected HTTP 400, got {status!r}"
    assert message == _PARENT_REJECTION, f"unexpected rejection message: {message!r}"

    ddl_code, ddl_status, ddl_message = _error(
        lambda: rs_data.get_statement_result(Id=subs[0]["Id"]))
    assert ddl_code == "ResourceNotFoundException", (
        f"reading the CREATE TABLE sub-statement's result must be rejected "
        f"ResourceNotFoundException, got {ddl_code!r}")
    assert ddl_status == 400, f"expected HTTP 400, got {ddl_status!r}"
    assert ddl_message == _NO_RESULT_MESSAGE, f"unexpected rejection message: {ddl_message!r}"

    # Each SELECT sub-statement serves its OWN rows under its OWN id.
    rows, page = _result(rs_data, subs[2]["Id"])
    assert rows == [[{"longValue": 1}, {"stringValue": "one"}],
                    [{"longValue": 2}, {"stringValue": "two"}]], (
        f"{DATAPLANE_MARKER}: the third sub-statement must serve the two inserted rows; got "
        f"{rows!r}")
    assert [c["name"] for c in page["ColumnMetadata"]] == ["k", "v"], (
        f"the sub-statement's column metadata must describe its own projection; got "
        f"{page.get('ColumnMetadata')!r}")
    counted, _ = _result(rs_data, subs[3]["Id"])
    assert counted == [[{"longValue": 2}]], (
        f"the fourth sub-statement must count the two rows the second one inserted; got "
        f"{counted!r}")

    # A sub-statement id is also a first-class DescribeStatement handle -- and its record there
    # reports ResultRows -1, not the count carried inside the parent's SubStatements entry.
    described_sub = _retrying(lambda: rs_data.describe_statement(Id=subs[2]["Id"]))
    assert described_sub["Status"] == "FINISHED", (
        f"describing a sub-statement id directly must work; got {described_sub!r}")
    assert described_sub["HasResultSet"] is True, (
        f"the directly-described SELECT sub-statement must report a result set; got "
        f"{described_sub.get('HasResultSet')!r}")
    assert described_sub["ResultRows"] == -1, (
        f"DescribeStatement on a sub-statement id reports ResultRows -1 while the parent's "
        f"SubStatements entry reports {_EXPECTED_SUB_RESULT_ROWS[2]}; got "
        f"{described_sub.get('ResultRows')!r}")


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
