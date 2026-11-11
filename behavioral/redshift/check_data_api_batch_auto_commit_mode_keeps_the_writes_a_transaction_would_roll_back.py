"""data-api-batch-auto-commit-mode-keeps-the-writes-a-transaction-would-roll-back."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-batch-auto-commit-mode-keeps-the-writes-a-transaction-would-roll-back"
GROUP = "sql-data-plane"
SERVICES = ["redshift"]


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Prefixes a failure in which the API accepted the SQL but the engine never ran it to completion.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
_CLUSTER_DEADLINE_S = 900
_DELETE_CLUSTER_DEADLINE_S = 300
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure noise under
    parallel runs, not a behavioral observation)."""
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
    """Poll *probe* until *done*. RAISES on timeout, never returns its last value."""
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


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region, read off the account."""
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
            raise AssertionError(
                f"no orderable {cluster_type} options in {rs.meta.region_name}; "
                f"DescribeOrderableClusterOptions returned nothing usable"
            )
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id, **overrides):
    """Cheapest shape that still proves the invariant: ONE node, not publicly accessible (the Data
    API reaches the cluster over the AWS-managed path, so no VPC and no ambient default VPC is
    needed), 1-day snapshot retention (RA3 refuses 0)."""
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
    )
    params.update(overrides)
    return params


def _create_cluster(rs, cluster_id, **overrides):
    """CreateCluster with a bounded retry on the association races."""
    deadline = time.monotonic() + 180
    while True:
        try:
            return _retrying(
                lambda: rs.create_cluster(**_cluster_params(rs, cluster_id, **overrides))
            )
        except ClientError as exc:
            if (
                _code_of(exc) not in _INVALID_STATE + ("InvalidIamRoleFault",)
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


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
    """Poll to a TERMINAL creation state, then assert it is `available`."""
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
    """Cost-leak teardown. Anything OTHER than not-found / wrong-state / throttle RAISES, so a
    leaked provisioned cluster is loud."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code not in _INVALID_STATE + _THROTTLE or time.monotonic() >= deadline:
                raise
        time.sleep(20)


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    """Poll DescribeStatement to a TERMINAL status (SUBMITTED/PICKED/STARTED are transient)."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=3,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _cell(record, i):
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


def _rows_of(rsd, statement_id):
    """Every row of a statement's result, paginated (GetStatementResult is token-paged)."""
    records, token = [], None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        resp = _retrying(lambda: rsd.get_statement_result(**kwargs))
        records.extend(resp.get("Records", []))
        token = resp.get("NextToken")
        if not token:
            break
    return records


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the statement id."""
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _ids(rsd, cluster_id, table, timeout_s=_WARM_STATEMENT_DEADLINE_S):
    """The table's whole contents, as a plain sorted list of ints. Read through
    ExecuteStatement+GetStatementResult — a DIFFERENT operation than the
    BatchExecuteStatement that wrote it."""
    statement_id = _run_sql(
        rsd, cluster_id, f"SELECT id FROM {table} ORDER BY id", timeout_s=timeout_s
    )
    return [_cell(row, 0) for row in _rows_of(rsd, statement_id)]


def _batch(rsd, cluster_id, sqls, timeout_s=_WARM_STATEMENT_DEADLINE_S, **kwargs):
    """Submit a batch and wait for the PARENT to reach a terminal status. Returns the
    DescribeStatement WITHOUT asserting on it — each caller asserts its own arm."""
    batch_id = _retrying(
        lambda: rsd.batch_execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=MASTER_USERNAME,
            Sqls=sqls,
            **kwargs,
        )
    )["Id"]
    return _wait_statement(rsd, batch_id, timeout_s=timeout_s)


def _assert_failed_at_the_middle(described, arm, sqls, *, third_runs):
    """The shape shared by all three failing arms: the parent FAILED, the middle sub-statement
    FAILED naming the offending column. Whether the THIRD sub-statement still runs to completion is
    the one thing that does NOT generalise across arms: under TRANSACTION (default and explicit) the
    batch stops dead at the failure, so the third sub-statement never runs; under AUTO_COMMIT every
    sub-statement is independently committed regardless of an earlier failure, so the third one runs
    and FINISHES. *third_runs* selects which of those two real, opposite outcomes this arm must
    show."""
    assert described["Status"] == "FAILED", (
        f"[{arm}] a batch containing a failing statement must reach FAILED, got "
        f"{described.get('Status')!r} error={described.get('Error')!r}"
    )
    subs = described["SubStatements"]
    assert len(subs) == len(sqls), (
        f"[{arm}] expected one SubStatement per submitted SQL ({len(sqls)}), got {len(subs)}"
    )
    assert subs[0]["Status"] == "FINISHED", (
        f"[{arm}] the first sub-statement ran before the failure, expected FINISHED, got "
        f"{subs[0].get('Status')!r}"
    )
    assert subs[1]["Status"] == "FAILED", (
        f"[{arm}] the broken sub-statement must be FAILED, got {subs[1].get('Status')!r}"
    )
    middle_error = subs[1].get("Error") or ""
    assert "no_such_column" in middle_error, (
        f"[{arm}] the failing sub-statement's Error must name the offending column so the failure "
        f"is the one this check broke and not something else; got {middle_error!r}"
    )
    if third_runs:
        assert subs[2]["Status"] == "FINISHED", (
            f"[{arm}] AUTO_COMMIT runs every sub-statement independently, so the one after the "
            f"failure must still run to completion, got {subs[2].get('Status')!r} for "
            f"{subs[2].get('QueryString')!r}"
        )
    else:
        assert subs[2]["Status"] != "FINISHED", (
            f"[{arm}] statements after the failure must not run to completion, got "
            f"{subs[2].get('Status')!r} for {subs[2].get('QueryString')!r}"
        )


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The same three-statement batch failing in the middle leaves the table empty under
    TRANSACTION (explicit or default) and keeps both the pre- and post-failure writes under
    AUTO_COMMIT; an all-valid AUTO_COMMIT batch keeping both rows is the positive control."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id for the caller, got {account!r}"
    )
    scenario = "rs-batch-execmode"

    cluster_id = ctx.unique_name("sim2real-behav-rs-execmode-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_execmode"
    _run_sql(rsd, cluster_id, f"CREATE TABLE {table} (id INT)")
    ctx.on_cleanup(lambda: _drop_table(rsd, cluster_id, table))
    baseline = _ids(rsd, cluster_id, table)
    assert baseline == [], (
        f"the table must start empty so each arm's surviving rows are unambiguous, got {baseline!r}"
    )

    def _failing(first, third):
        return [
            f"INSERT INTO {table} VALUES ({first})",
            # The one broken thing, identical in every arm: no_such_column does not exist.
            f"INSERT INTO {table} SELECT no_such_column FROM {table}",
            f"INSERT INTO {table} VALUES ({third})",
        ]

    # ---- arm 1: the DEFAULT (ExecutionMode omitted) is transactional ----
    default_sqls = _failing(10, 11)
    _assert_failed_at_the_middle(
        _batch(rsd, cluster_id, default_sqls), "default", default_sqls, third_runs=False
    )
    after_default = _ids(rsd, cluster_id, table)
    assert after_default == [], (
        f"omitting ExecutionMode must behave as TRANSACTION, so the failed batch rolls ALL of it "
        f"back and the table is unchanged; expected [], got {after_default!r}"
    )

    # ---- arm 2: the explicit TRANSACTION value agrees with the default ----
    txn_sqls = _failing(20, 21)
    _assert_failed_at_the_middle(
        _batch(rsd, cluster_id, txn_sqls, ExecutionMode="TRANSACTION"),
        "TRANSACTION",
        txn_sqls,
        third_runs=False,
    )
    after_txn = _ids(rsd, cluster_id, table)
    assert after_txn == [], (
        f"ExecutionMode='TRANSACTION' must roll the whole failed batch back; expected [], got "
        f"{after_txn!r}"
    )

    # ---- arm 3: AUTO_COMMIT runs every sub-statement independently ----
    # AUTO_COMMIT does not stop at the first failure: the parent still reaches FAILED, but the
    # third sub-statement runs to completion and its write survives; only the failing one's is lost.
    auto_sqls = _failing(30, 31)
    _assert_failed_at_the_middle(
        _batch(rsd, cluster_id, auto_sqls, ExecutionMode="AUTO_COMMIT"),
        "AUTO_COMMIT",
        auto_sqls,
        third_runs=True,
    )
    after_auto = _ids(rsd, cluster_id, table)
    assert after_auto == [30, 31], (
        f"ExecutionMode='AUTO_COMMIT' commits every sub-statement independently regardless of an "
        f"earlier failure, so BOTH the write before the failure and the write after it must "
        f"survive; expected [30, 31], got {after_auto!r}. [] means the target rolled back a batch "
        f"it was told not to (the same answer it gives for TRANSACTION, so ExecutionMode is being "
        f"ignored); [30] means it stopped at the first failure instead of treating each "
        f"sub-statement independently"
    )
    # ---- restore: the corrected AUTO_COMMIT batch commits all of it ----
    good_sqls = [
        f"INSERT INTO {table} VALUES (40)",
        f"INSERT INTO {table} VALUES (41)",
    ]
    repaired = _batch(rsd, cluster_id, good_sqls, ExecutionMode="AUTO_COMMIT")
    assert repaired["Status"] == "FINISHED", (
        f"an all-valid AUTO_COMMIT batch must FINISH, got {repaired.get('Status')!r} "
        f"error={repaired.get('Error')!r}"
    )
    assert [s["Status"] for s in repaired["SubStatements"]] == ["FINISHED"] * len(good_sqls), (
        f"every sub-statement of a FINISHED batch must be FINISHED, got "
        f"{[s.get('Status') for s in repaired['SubStatements']]!r}"
    )

    # Terminal assertion: an independent read through a different operation, showing the union of
    # what every arm was supposed to leave behind. A target on which nothing commits cannot reach
    # this line, which is what makes the three arms above evidence rather than coincidence.
    final = _ids(rsd, cluster_id, table)
    assert final == [30, 31, 40, 41], (
        f"the table must hold exactly the two AUTO_COMMIT survivors and the two repaired rows: "
        f"expected [30, 31, 40, 41], got {final!r}"
    )


def _drop_table(rsd, cluster_id, table):
    """Teardown. The DROP's own terminal status is not asserted — teardown must not decide the
    verdict — but it is waited for so the table is really gone before the cluster delete starts."""
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=MASTER_USERNAME,
            Sql=f"DROP TABLE IF EXISTS {table}",
        )
    )["Id"]
    _wait_statement(rsd, statement_id, timeout_s=_WARM_STATEMENT_DEADLINE_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
