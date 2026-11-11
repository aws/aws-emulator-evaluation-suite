"""data-api-wait-time-seconds-returns-a-terminal-status-without-a-poll."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Redshift's leader-node result cache is keyed on exact statement text, so each timed submission
# carries a distinct always-false predicate constant: the SQL text differs every time while cost
# and result stay identical.

CHECK = "data-api-wait-time-seconds-returns-a-terminal-status-without-a-poll"
GROUP = "sql-data-plane"
SERVICES = ["redshift"]


# ===== helpers (self-contained) =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
_CLUSTER_DEADLINE_S = 900
_DELETE_CLUSTER_DEADLINE_S = 300
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# The three non-terminal values of the modelled six (SUBMITTED, PICKED, STARTED, FINISHED, ABORTED,
# FAILED) — an accept-set that is strictly smaller than the enum, so it can fail.
_NON_TERMINAL_STATEMENT = ("SUBMITTED", "PICKED", "STARTED")
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120

# WaitTimeSeconds is modelled range [1, 30].
_SHORT_WAIT_S = 2
_LONG_WAIT_S = 30
# The floor a blocking call must respect, as a fraction of the wait it was asked for. AWS checks
# status on its own cadence and can return a WaitTimeSeconds=2 call on a non-terminal statement
# after ~1.45 s, so 0.5 leaves headroom while still failing hard against a target that ignores the
# field and returns in milliseconds.
_WAIT_FLOOR_RATIO = 0.5
# The ceiling: the call must not block materially past its own budget. Generous, because it is
# bounding a server-side wait plus SDK/network time, not measuring performance.
_WAIT_CEILING_SLACK_S = 20
# The widener query must be genuinely slower than the short wait for the floor leg to mean
# anything, and the check ESTABLISHES that from the target's own reported Duration rather than
# assuming it.
#
# The self-join predicate `a.n + b.n = -1` is an arithmetic expression, not a column equality, so
# it gets no usable hash key; growth on a dc2.large is sub-quadratic (about 2 s at 20000 rows), so
# the widener is a 5-digit base-10 cross product (0..99999, exact row count by construction).
_WIDENER_ROWS = 80000
_SLOW_FLOOR_S = 3.0


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure noise under
    parallel runs, not a behavioral observation). NOT used for the timed calls below, where a
    retry would corrupt the measurement."""
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
    """Cheapest shape that still proves the invariant: ONE node, not publicly accessible, 1-day
    snapshot retention (RA3 refuses 0)."""
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=ADMIN_USERNAME,
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
            time.sleep(10)


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
    """Cost-leak teardown. Anything OTHER than not-found / wrong-state / throttle RAISES."""
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
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=3,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _cell(record, i):
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


def _submit(rsd, cluster_id, sql, **kwargs):
    return _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql,
            **kwargs,
        )
    )


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the DescribeStatement."""
    statement_id = _submit(rsd, cluster_id, sql)["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return described


def _timed_submit(rsd, cluster_id, sql, **kwargs):
    """ExecuteStatement, returning (response, elapsed_seconds). Deliberately NOT wrapped in
    _retrying: a throttle retry would silently inflate the measurement, so a throttle here must
    surface as an error rather than a wrong number."""
    started = time.monotonic()
    response = rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql, **kwargs
    )
    return response, time.monotonic() - started


def _drop_table(rsd, cluster_id, table):
    """Teardown; the DROP's terminal status is not asserted, but it is waited for."""
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=ADMIN_USERNAME,
            Sql=f"DROP TABLE IF EXISTS {table}",
        )
    )["Id"]
    _wait_statement(rsd, statement_id, timeout_s=_WARM_STATEMENT_DEADLINE_S)


# timing:real-time — lease: 2 s https://docs.aws.amazon.com/redshift-data/latest/APIReference/API_ExecuteStatement.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """`WaitTimeSeconds` makes ExecuteStatement synchronous: a fast statement returns a terminal
    Status in the submit response so GetStatementResult needs no poll, and a slower one returns
    non-terminal after waiting at least ~50% of the requested time.
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id, got {account!r}"
    )
    scenario = "rs-waittime"

    cluster_id = ctx.unique_name("sim2real-behav-rs-waittime-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    seed = "sim2real_behav_wait_seed"
    filler = "sim2real_behav_wait_filler"
    fast_table = "sim2real_behav_wait_fast"
    for name in (seed, filler, fast_table):
        ctx.on_cleanup(lambda n=name: _drop_table(rsd, cluster_id, n))

    # This first statement absorbs connection establishment, so every measurement below is on a
    # warm path and the elapsed numbers mean what they say.
    _run_sql(rsd, cluster_id, f"CREATE TABLE {fast_table} (id INT)")
    _run_sql(rsd, cluster_id, f"INSERT INTO {fast_table} VALUES (7)")

    _run_sql(rsd, cluster_id, f"CREATE TABLE {seed} (n INT)", timeout_s=_WARM_STATEMENT_DEADLINE_S)
    _run_sql(
        rsd,
        cluster_id,
        f"INSERT INTO {seed} VALUES " + ", ".join(f"({n})" for n in range(10)),
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
    )
    _run_sql(
        rsd, cluster_id, f"CREATE TABLE {filler} (n INT)", timeout_s=_WARM_STATEMENT_DEADLINE_S
    )
    _run_sql(
        rsd,
        cluster_id,
        f"INSERT INTO {filler} SELECT a.n * 10000 + b.n * 1000 + c.n * 100 + d.n * 10 + e.n "
        f"FROM {seed} a, {seed} b, {seed} c, {seed} d, {seed} e "
        f"WHERE a.n * 10000 + b.n * 1000 + c.n * 100 + d.n * 10 + e.n < {_WIDENER_ROWS}",
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
    )
    loaded = _rows_of(
        rsd,
        _run_sql(
            rsd, cluster_id, f"SELECT count(*) FROM {filler}",
            timeout_s=_WARM_STATEMENT_DEADLINE_S,
        )["Id"],
    )
    assert _cell(loaded[0], 0) == _WIDENER_ROWS, (
        f"the widener table must hold exactly {_WIDENER_ROWS} rows for the timing below to be "
        f"reproducible, got {_cell(loaded[0], 0)!r}"
    )

    # Redshift caches query RESULTS keyed on exact statement text: submitting the identical SQL a
    # second time returns instantly from the leader-node cache, not from re-running the join. That
    # would make arm 1/2's re-submission of "the same slow query" spuriously fast and prove
    # nothing about WaitTimeSeconds. Each timed submission below gets its own always-false
    # predicate constant (this alone is enough to force a fresh execution) so the SQL
    # text differs every time while the cost and the (empty) result stay identical.
    def _widener_sql(nonce):
        return f"SELECT count(*) FROM {filler} a, {filler} b WHERE a.n + b.n = {-(nonce + 1)}"

    # ---- establish the premise from the target's own reported Duration ----
    measured = _run_sql(rsd, cluster_id, _widener_sql(0), timeout_s=_WARM_STATEMENT_DEADLINE_S)
    duration_ns = measured.get("Duration")
    assert isinstance(duration_ns, int) and duration_ns > 0, (
        f"a FINISHED statement must report a positive Duration, got {duration_ns!r}"
    )
    duration_s = duration_ns / 1_000_000_000
    assert duration_s >= _SLOW_FLOOR_S, (
        f"the widener query must take at least {_SLOW_FLOOR_S}s on this cluster for the "
        f"WaitTimeSeconds floor below to test anything; DescribeStatement reported "
        f"{duration_s:.2f}s. RAISE _WIDENER_ROWS (currently {_WIDENER_ROWS}) rather than "
        f"weakening the assertion"
    )

    # ---- arm 1: no WaitTimeSeconds -> the submit is asynchronous ----
    async_response, async_elapsed = _timed_submit(rsd, cluster_id, _widener_sql(1))
    # With no WaitTimeSeconds, ExecuteStatement's response carries no `Status` and no
    # `HasResultSet` at all -- the server computes and returns those fields only when
    # WaitTimeSeconds asks it to wait and check. A target that fabricates any Status here, even a
    # plausible SUBMITTED, diverges from the real contract exactly as much as one that fills in
    # FINISHED.
    assert "Status" not in async_response, (
        f"ExecuteStatement with no WaitTimeSeconds must not report a Status at all; got "
        f"Status={async_response.get('Status')!r} in response={async_response!r}"
    )
    assert "HasResultSet" not in async_response, (
        f"ExecuteStatement with no WaitTimeSeconds must not report HasResultSet either; got "
        f"HasResultSet={async_response.get('HasResultSet')!r} in response={async_response!r}"
    )
    assert async_elapsed < duration_s, (
        f"the asynchronous submit must return well before the query it submitted completes: the "
        f"submit took {async_elapsed:.2f}s and the query takes {duration_s:.2f}s"
    )
    _wait_statement(rsd, async_response["Id"], timeout_s=_WARM_STATEMENT_DEADLINE_S)

    # ---- arm 2: a wait SHORTER than the statement -> non-terminal, after really waiting ----
    short_response, short_elapsed = _timed_submit(
        rsd, cluster_id, _widener_sql(2), WaitTimeSeconds=_SHORT_WAIT_S
    )
    assert short_response["Status"] in _NON_TERMINAL_STATEMENT, (
        f"a {_SHORT_WAIT_S}s wait on a {duration_s:.2f}s query must time out and return a "
        f"non-terminal Status from {_NON_TERMINAL_STATEMENT!r}; got "
        f"{short_response.get('Status')!r}"
    )
    floor = _SHORT_WAIT_S * _WAIT_FLOOR_RATIO
    assert short_elapsed >= floor, (
        f"WaitTimeSeconds={_SHORT_WAIT_S} must actually BLOCK: the call returned after "
        f"{short_elapsed:.2f}s, below the {floor:.2f}s floor. Returning immediately means the "
        f"field was accepted and ignored"
    )
    ceiling = _SHORT_WAIT_S + _WAIT_CEILING_SLACK_S
    assert short_elapsed <= ceiling, (
        f"WaitTimeSeconds={_SHORT_WAIT_S} is a CEILING as well as a floor: the call took "
        f"{short_elapsed:.2f}s, past {ceiling:.2f}s"
    )
    # The statement it submitted is genuinely still running, not finished-and-mislabelled.
    still_running = _retrying(lambda: rsd.describe_statement(Id=short_response["Id"]))
    assert still_running["Status"] in _NON_TERMINAL_STATEMENT + ("FINISHED",), (
        f"the statement behind the timed-out wait must be running or already finished, never "
        f"FAILED or ABORTED; DescribeStatement said {still_running.get('Status')!r} "
        f"error={still_running.get('Error')!r}"
    )
    _wait_statement(rsd, short_response["Id"], timeout_s=_WARM_STATEMENT_DEADLINE_S)

    # ---- arm 3: a wait LONGER than the statement -> terminal in the submit response ----
    fast_sql = f"SELECT id FROM {fast_table} ORDER BY id"
    sync_response, sync_elapsed = _timed_submit(
        rsd, cluster_id, fast_sql, WaitTimeSeconds=_LONG_WAIT_S
    )
    assert sync_response["Status"] == "FINISHED", (
        f"a {_LONG_WAIT_S}s wait on a trivial SELECT must return FINISHED in the ExecuteStatement "
        f"RESPONSE, with no DescribeStatement poll; got {sync_response.get('Status')!r}"
    )
    assert sync_response["HasResultSet"] is True, (
        f"the synchronous response must report HasResultSet=True for a SELECT, got "
        f"{sync_response.get('HasResultSet')!r}"
    )
    sync_ceiling = _LONG_WAIT_S + _WAIT_CEILING_SLACK_S
    assert sync_elapsed <= sync_ceiling, (
        f"WaitTimeSeconds={_LONG_WAIT_S} must not block past its own budget: the call took "
        f"{sync_elapsed:.2f}s, past {sync_ceiling:.2f}s"
    )

    # Terminal assertion: an INDEPENDENT read at the destination, through a different operation
    # (GetStatementResult), issued with NO DescribeStatement in between — which is only legitimate
    # because the submit response already said FINISHED.
    rows = _rows_of(rsd, sync_response["Id"])
    assert [_cell(row, 0) for row in rows] == [7], (
        f"GetStatementResult must be callable straight after a synchronous submit and return the "
        f"row the SELECT asked for: expected [7], got {rows!r}"
    )

    # Freeze detector: reads must not advance state. Three consecutive DescribeStatement calls
    # on the finished statement must report the same terminal status and the same UpdatedAt.
    first = _retrying(lambda: rsd.describe_statement(Id=sync_response["Id"]))
    assert first["Status"] == "FINISHED", (
        f"DescribeStatement must agree with the synchronous submit that the statement FINISHED, "
        f"got {first.get('Status')!r}"
    )
    for attempt in range(2):
        again = _retrying(lambda: rsd.describe_statement(Id=sync_response["Id"]))
        assert (again["Status"], again.get("UpdatedAt")) == (
            first["Status"],
            first.get("UpdatedAt"),
        ), (
            f"read {attempt + 2} of 3: DescribeStatement is a pure read and must not advance the "
            f"record: expected (Status, UpdatedAt) == "
            f"({first['Status']!r}, {first.get('UpdatedAt')!r}), got "
            f"({again.get('Status')!r}, {again.get('UpdatedAt')!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
