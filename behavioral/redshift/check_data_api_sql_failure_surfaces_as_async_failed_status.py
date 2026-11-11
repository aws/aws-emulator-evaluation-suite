"""data-api-sql-failure-surfaces-as-async-failed-status."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-sql-failure-surfaces-as-async-failed-status"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

# A syntactically valid statement id that was never issued, used as the contrast case for the
# "no result" refusal below. The nil UUID is safe: the Data API accepts the shape and reports
# ResourceNotFoundException "Query does not exist." for it.
_UNKNOWN_STATEMENT_ID = "00000000-0000-0000-0000-000000000000"


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


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _err_detail(fn):
    """Like _err, but returns (code, message).

    The message is needed because the Data API answers "this statement has no result" and "there
    is no such statement" with the SAME error code and different messages, and the check has to
    tell those two apart.
    """
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return f"EXC:{type(exc).__name__}", str(exc)
    return "OK", ""


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


def _submit(rsd, cluster_id, sql):
    return _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql
        )
    )


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    statement_id = _submit(rsd, cluster_id, sql)["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} did not FINISH: status={described['Status']!r} error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql):
    return _retrying(lambda: rsd.get_statement_result(Id=_run_sql(rsd, cluster_id, sql)))["Records"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SQL error in a Data API statement surfaces asynchronously as DescribeStatement
    Status FAILED with a populated Error, not as an ExecuteStatement error: GetStatementResult is
    refused, nothing is written, and the corrected statement FINISHES."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-behav-rs-sqlfail-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_sqlfail"
    _run_sql(rsd, cluster_id, f"CREATE TABLE {table} (id INT, val VARCHAR(16))")
    _run_sql(rsd, cluster_id, f"INSERT INTO {table} VALUES (1, 'kept')")
    baseline = _select(rsd, cluster_id, f"SELECT COUNT(*) FROM {table}")
    assert baseline == [[{"longValue": 1}]], f"setup did not leave exactly one row: {baseline!r}"

    # Break exactly one thing: no_such_column does not exist on the table.
    bad_sql = f"SELECT id, no_such_column FROM {table}"
    accepted = _submit(rsd, cluster_id, bad_sql)
    bad_id = accepted["Id"]
    assert bad_id, (
        "ExecuteStatement must ACCEPT a syntactically valid statement and surface the SQL "
        f"error asynchronously; got {accepted!r}"
    )

    failed = _wait_statement(rsd, bad_id)
    assert failed["Status"] == "FAILED", (
        f"a statement referencing a missing column must reach FAILED, got {failed.get('Status')!r} "
        f"(error={failed.get('Error')!r})"
    )
    assert failed.get("Error"), "a FAILED statement must carry a non-empty Error"
    assert "no_such_column" in failed["Error"], (
        f"the Error must name the offending column, got {failed['Error']!r}"
    )
    assert failed.get("HasResultSet") in (None, False), (
        f"a FAILED statement must not claim a result set, got {failed.get('HasResultSet')!r}"
    )
    assert failed["QueryString"] == bad_sql, failed.get("QueryString")

    # GetStatementResult on a FAILED statement is refused.
    # The refusal is ResourceNotFoundException, not ValidationException -- the Data API models "there is no result
    # to fetch" as a missing RESULT resource, even though the statement itself demonstrably exists.
    # The code alone is therefore ambiguous, because an unknown statement id raises the same code, so
    # the two are separated by message and by the fact that DescribeStatement still resolves the id:
    #   FAILED statement    -> "Query does not have result. Please check query status with
    #                           DescribeStatement."
    #   unknown statement id -> "Query does not exist."
    # A target that returns an empty result set here, or that 404s a statement it just described,
    # fails.
    result_code, result_message = _err_detail(lambda: rsd.get_statement_result(Id=bad_id))
    assert result_code == "ResourceNotFoundException", (
        f"GetStatementResult on a FAILED statement must be refused with ResourceNotFoundException, "
        f"got {result_code} ({result_message!r})"
    )
    no_result = "Query does not have result. Please check query status with DescribeStatement."
    assert result_message == no_result, (
        "the refusal must say the statement has no RESULT (not that the statement is unknown), got "
        f"{result_message!r}"
    )
    unknown_code, unknown_message = _err_detail(
        lambda: rsd.get_statement_result(Id=_UNKNOWN_STATEMENT_ID)
    )
    assert unknown_code == "ResourceNotFoundException", (
        f"an unknown statement id must also be ResourceNotFoundException, got {unknown_code}"
    )
    assert unknown_message == "Query does not exist.", (
        f"an unknown statement id must be refused as a missing statement, got {unknown_message!r}"
    )
    assert unknown_message != result_message, (
        "a statement with no result and a statement that does not exist share a code and must be "
        f"distinguishable by message; both said {result_message!r}"
    )
    # ...and the failed statement is still very much there: only its result is missing.
    still_described = _retrying(lambda: rsd.describe_statement(Id=bad_id))
    assert still_described["Status"] == "FAILED", (
        f"the FAILED statement must remain describable after its result was refused, got "
        f"{still_described.get('Status')!r}"
    )

    # Effect absent: the failed statement wrote nothing.
    after = _select(rsd, cluster_id, f"SELECT COUNT(*) FROM {table}")
    assert after == [[{"longValue": 1}]], (
        f"a FAILED statement must not change the table, expected one row, got {after!r}"
    )

    # The failed statement is classified as FAILED in the statement history, not FINISHED.
    failed_ids = [
        s["Id"]
        for s in _retrying(
            lambda: rsd.list_statements(ClusterIdentifier=cluster_id, Status="FAILED", MaxResults=20)
        )["Statements"]
    ]
    assert bad_id in failed_ids, f"ListStatements(Status=FAILED) must include {bad_id}, got {failed_ids}"
    finished_ids = [
        s["Id"]
        for s in _retrying(
            lambda: rsd.list_statements(
                ClusterIdentifier=cluster_id, Status="FINISHED", MaxResults=20
            )
        )["Statements"]
    ]
    assert bad_id not in finished_ids, (
        f"a FAILED statement must not also be listed as FINISHED, got {finished_ids}"
    )

    # Control: the same query with the correct column still works.
    control = _select(rsd, cluster_id, f"SELECT id, val FROM {table} ORDER BY id")
    assert control == [[{"longValue": 1}, {"stringValue": "kept"}]], (
        f"the corrected statement must still FINISH and return the row, got {control!r}"
    )

    _run_sql(rsd, cluster_id, f"DROP TABLE {table}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
