"""rdapi-failed-statement-reports-error-and-result-read-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rdapi-failed-statement-reports-error-and-result-read-rejected"
GROUP = "async-data-api"
SERVICES = ["redshift"]

_TABLE = "sim2real_rdapi_control"
_ABSENT = "sim2real_rdapi_absent_table"
# The SQL error arrives in the ASYNC
# record, not as an API error: ExecuteStatement returns 200 with an id.
_EXPECTED_ERROR = f'ERROR: relation "{_ABSENT}" does not exist'
_NO_RESULT_MESSAGE = "Query does not have result. Please check query status with DescribeStatement."


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A statement whose SQL cannot run lands FAILED with the engine's own error text, has no result
    set and creates nothing, while a valid statement on the same cluster still returns its rows."""
    rs_data = ctx.client("redshift-data")
    cluster_id = _provision_cluster(ctx, "rdapi-failed")

    # Full setup: a real table with a real row, so "no effect" below is a claim about state that
    # exists and could have changed.
    _run_sql(rs_data, cluster_id, f"CREATE TABLE {_TABLE} (id INT)")
    _run_sql(rs_data, cluster_id, f"INSERT INTO {_TABLE} VALUES (1)")

    # Break exactly one thing: read a relation that does not exist.
    failed = _describe_sql(rs_data, cluster_id, f"SELECT * FROM {_ABSENT}")

    assert failed["Status"] == "FAILED", (
        f"a statement over a missing relation must land FAILED, got {failed['Status']!r} "
        f"error={failed.get('Error')!r}")
    assert failed.get("Error") == _EXPECTED_ERROR, (
        f"the async record must carry the engine's own error text; got {failed.get('Error')!r} "
        f"want {_EXPECTED_ERROR!r}")
    assert failed["HasResultSet"] is False, (
        f"a failed statement has no result set, so HasResultSet must be False, got "
        f"{failed.get('HasResultSet')!r}")
    assert failed["ResultRows"] == -1 and failed["ResultSize"] == -1, (
        f"a failed statement must report ResultRows/ResultSize as -1 (unknown), not 0; got "
        f"{failed.get('ResultRows')!r}/{failed.get('ResultSize')!r}")

    # (a) the specific error code for reading its result...
    code, status, message = _error(lambda: rs_data.get_statement_result(Id=failed["Id"]))
    assert code == "ResourceNotFoundException", (
        f"reading a failed statement's result must be rejected ResourceNotFoundException, got "
        f"{code!r}")
    assert status == 400, f"ResourceNotFoundException here is an HTTP 400, not a 404; got {status!r}"
    assert message == _NO_RESULT_MESSAGE, (
        f"the rejection must point the caller at DescribeStatement; got {message!r}")

    # (b) the effect is absent: the failed read neither created the relation nor touched the table.
    created = _select(rs_data, cluster_id,
                      "SELECT count(*) FROM pg_tables WHERE tablename = "
                      f"'{_ABSENT}'")
    assert created == [[{"longValue": 0}]], (
        f"a failed read must not bring its relation into existence; pg_tables says {created!r}")
    rows = _select(rs_data, cluster_id, f"SELECT id FROM {_TABLE} ORDER BY id")
    assert rows == [[{"longValue": 1}]], (
        f"the failed statement must leave the pre-existing row untouched; got {rows!r}")

    # (c) the positive control, on the same cluster and in the same file.
    control_id = _run_sql(rs_data, cluster_id, f"SELECT count(*) FROM {_TABLE}")
    control = _result(rs_data, control_id)[0]
    assert control == [[{"longValue": 1}]], (
        f"{DATAPLANE_MARKER}: a valid statement on the same cluster must still return its rows; "
        f"got {control!r}")


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
