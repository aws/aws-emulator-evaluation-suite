"""data-api-session-transaction-hides-uncommitted-rows-from-a-second-session."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-session-transaction-hides-uncommitted-rows-from-a-second-session"
GROUP = "state-machine"
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

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
# A single-node dc2.large reaches `available` in
# ~60-90 s. The bounded deadline still FAILS rather than hanging, and _wait_until returns the
# instant the cluster is available, so a fast target pays nothing for the headroom.
_CLUSTER_DEADLINE_S = 900
# Teardown has 1800 s in all: the DROP teardown before it takes up to 120 s, with a margin for the
# rest, so the cluster delete and its wait for ClusterNotFound take what is left.
_DELETE_CLUSTER_DEADLINE_S = 1500
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# The first Data API statement against a freshly-available cluster includes connection
# establishment, so its deadline is deliberately larger than a warm query's.
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120
# Long enough that the session cannot idle out between the legs below; well under the documented
# 24h ceiling for SessionKeepAliveSeconds.
_SESSION_KEEP_ALIVE_S = 900


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
    """Poll *probe* until *done*. RAISES on timeout so a truncated poll can never be mistaken for
    the condition holding, and never returns its last value."""
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
    API reaches the cluster over the AWS-managed path, so no VPC, no security group and no ambient
    default VPC is needed), 1-day snapshot retention (RA3 refuses 0)."""
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
    """CreateCluster with a bounded retry on the association races: a dependency created seconds
    ago is not always visible to the Redshift control plane, which rejects outright rather than
    converging."""
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
    """Poll to a TERMINAL creation state, then assert it is `available`. The terminal set includes
    the failure states so the poll cannot spin on them; the assertion after it refuses them."""
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
    """Cost-leak teardown. SkipFinalClusterSnapshot=True so no snapshot blocks the delete and none
    is left billing; a cluster still `creating` refuses deletion, so that is retried, then the
    asynchronous delete is waited out to ClusterNotFound, under one deadline. Anything OTHER than
    not-found / wrong-state / throttle RAISES, so a leak is loud."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code not in _INVALID_STATE + _THROTTLE or time.monotonic() >= deadline:
                raise
        time.sleep(20)
    _wait_cluster_gone(rs, cluster_id, deadline)


def _wait_cluster_gone(rs, cluster_id, deadline):
    """Poll DescribeClusters every 2 s until it answers ClusterNotFound; raise at *deadline*."""
    while True:
        try:
            clusters = rs.describe_clusters(ClusterIdentifier=cluster_id).get("Clusters", [])
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            raise
        if time.monotonic() >= deadline:
            status = clusters[0].get("ClusterStatus") if clusters else None
            raise TimeoutError(f"cluster {cluster_id} still listed ({status!r}) at the teardown "
                               f"deadline")
        time.sleep(2)


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
    """Every row of a FINISHED statement's result, paginated (GetStatementResult is token-paged)."""
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


def _open_session(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Run *sql* on a NEW session that stays alive afterwards, and return (session_id,
    statement_id). Asserts the statement FINISHED and that a SessionId came back at all."""
    submitted = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=ADMIN_USERNAME,
            Sql=sql,
            SessionKeepAliveSeconds=_SESSION_KEEP_ALIVE_S,
        )
    )
    session_id = submitted.get("SessionId")
    assert session_id, (
        f"ExecuteStatement with SessionKeepAliveSeconds={_SESSION_KEEP_ALIVE_S} must return a "
        f"SessionId so the session can be reused; got {submitted!r}"
    )
    described = _wait_statement(rsd, submitted["Id"], timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the session-opening statement {sql!r} did not FINISH: "
        f"status={described['Status']!r} error={described.get('Error')!r}"
    )
    return session_id, submitted["Id"]


def _in_session(rsd, session_id, sql, timeout_s=_WARM_STATEMENT_DEADLINE_S, expect="FINISHED"):
    """Run *sql* on an EXISTING session and return the DescribeStatement. Neither
    WorkgroupName/ClusterIdentifier nor Database may be supplied alongside SessionId — the session
    already carries its connection identity from when it was opened."""
    submitted = _retrying(
        lambda: rsd.execute_statement(
            Sql=sql, SessionId=session_id, SessionKeepAliveSeconds=_SESSION_KEEP_ALIVE_S
        )
    )
    assert submitted.get("SessionId") == session_id, (
        f"a statement submitted with SessionId={session_id!r} must report that same SessionId "
        f"back, got {submitted.get('SessionId')!r}"
    )
    described = _wait_statement(rsd, submitted["Id"], timeout_s=timeout_s)
    assert described["Status"] == expect, (
        f"{DATAPLANE_MARKER}: {sql!r} in session {session_id!r} must reach {expect!r}, got "
        f"status={described['Status']!r} error={described.get('Error')!r}"
    )
    assert described.get("SessionId") == session_id, (
        f"DescribeStatement must report the SessionId the statement ran in: expected "
        f"{session_id!r}, got {described.get('SessionId')!r}"
    )
    return described


def _count_in_session(rsd, session_id, table):
    """`SELECT count(*)` as seen from *session_id*. The scalar, not the envelope."""
    described = _in_session(rsd, session_id, f"SELECT count(*) FROM {table}")
    rows = _rows_of(rsd, described["Id"])
    assert len(rows) == 1 and len(rows[0]) == 1, (
        f"a count(*) must return exactly one row of one column, got {rows!r}"
    )
    value = _cell(rows[0], 0)
    assert isinstance(value, int), (
        f"count(*) must come back as an integer Field member, got {rows[0]!r}"
    )
    return value


def _count_fresh(rsd, cluster_id, table):
    """`SELECT count(*)` from a BRAND-NEW connection with no SessionId at all — the independent
    third observer, used for the terminal reads."""
    submitted = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=ADMIN_USERNAME,
            Sql=f"SELECT count(*) FROM {table}",
        )
    )
    assert not submitted.get("SessionId"), (
        f"a statement submitted WITHOUT SessionKeepAliveSeconds must not report a reusable "
        f"SessionId, got {submitted.get('SessionId')!r}"
    )
    described = _wait_statement(rsd, submitted["Id"], timeout_s=_WARM_STATEMENT_DEADLINE_S)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the independent count did not FINISH: "
        f"status={described['Status']!r} error={described.get('Error')!r}"
    )
    rows = _rows_of(rsd, described["Id"])
    assert len(rows) == 1 and len(rows[0]) == 1, (
        f"a count(*) must return exactly one row of one column, got {rows!r}"
    )
    return _cell(rows[0], 0)


def _drop_table(rsd, cluster_id, table):
    """Teardown on a fresh connection: a session left holding a transaction cannot be relied on to
    run the DROP, and the DROP must not be able to hide behind one."""
    submitted = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=ADMIN_USERNAME,
            Sql=f"DROP TABLE IF EXISTS {table}",
        )
    )
    _wait_statement(rsd, submitted["Id"], timeout_s=_WARM_STATEMENT_DEADLINE_S)


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "plane:data",
    "dp:api",
)
def run(ctx) -> None:
    """A transaction opened in one Data API session is isolated: its uncommitted INSERT is
    visible to its own session but not to a second one, COMMIT makes it visible there, and
    ROLLBACK removes it for everyone."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id for the caller, got {account!r}"
    )
    scenario = "rs-session-isolation"

    cluster_id = ctx.unique_name("sim2real-behav-rs-sessiso-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_session_iso"

    # Session A is opened by the DDL itself, so the table exists on a committed, shared basis
    # before either session reads it. DDL outside a transaction auto-commits.
    session_a, _ = _open_session(rsd, cluster_id, f"CREATE TABLE {table} (id INT)")
    # Registered as soon as the table can exist; DROP runs on a fresh connection so a wedged
    # session cannot block teardown.
    ctx.on_cleanup(lambda: _drop_table(rsd, cluster_id, table))

    session_b, _ = _open_session(
        rsd, cluster_id, "SELECT 1", timeout_s=_WARM_STATEMENT_DEADLINE_S
    )
    assert session_b != session_a, (
        f"two independently opened sessions must have DIFFERENT SessionIds; both were "
        f"{session_a!r}, so the target is handing back one shared session"
    )

    # Both sessions are real, server-side objects the API will own up to. ListSessions rejects
    # SessionId combined with ANY other filter, so SessionId alone is the only valid way to look one
    # up; ClusterIdentifier is still checked below, but from the response body rather than as a
    # request filter.
    for label, session_id in (("A", session_a), ("B", session_b)):
        listed = _retrying(lambda: rsd.list_sessions(SessionId=session_id))["Sessions"]
        assert len(listed) == 1, (
            f"ListSessions filtered to session {label} ({session_id!r}) must return exactly one "
            f"SessionData, got {listed!r}"
        )
        assert listed[0]["SessionId"] == session_id, (
            f"ListSessions must echo the requested SessionId for session {label}: expected "
            f"{session_id!r}, got {listed[0].get('SessionId')!r}"
        )
        assert listed[0]["Status"] in ("AVAILABLE", "BUSY"), (
            f"session {label} ({session_id!r}) must be AVAILABLE or BUSY between statements, got "
            f"{listed[0].get('Status')!r}"
        )
        assert listed[0].get("ClusterIdentifier") == cluster_id, (
            f"session {label} must report the cluster it is connected to: expected "
            f"{cluster_id!r}, got {listed[0].get('ClusterIdentifier')!r}"
        )

    # Baseline: both sessions and an independent third connection agree the table is empty.
    assert _count_in_session(rsd, session_a, table) == 0, (
        "session A must see an empty table before anything is inserted"
    )
    assert _count_in_session(rsd, session_b, table) == 0, (
        "session B must see an empty table before anything is inserted"
    )
    assert _count_fresh(rsd, cluster_id, table) == 0, (
        "an independent connection must see an empty table before anything is inserted"
    )

    # ---- leg 1: an OPEN transaction's write is private to its own session ----
    _in_session(rsd, session_a, f"BEGIN; INSERT INTO {table} VALUES (1)")

    a_sees = _count_in_session(rsd, session_a, table)
    assert a_sees == 1, (
        f"session A must see its OWN uncommitted INSERT: expected 1 row, got {a_sees}. 0 means "
        f"the INSERT never reached the engine or was rolled back immediately"
    )

    # Freeze detector: three consecutive reads from session B, all of which must be blind to
    # the open transaction. Structural barrier — no COMMIT has been issued, so there is nothing to
    # wait for and no window to calibrate.
    for attempt in range(3):
        b_sees = _count_in_session(rsd, session_b, table)
        assert b_sees == 0, (
            f"read {attempt + 1} of 3: session B must NOT see session A's UNCOMMITTED row: "
            f"expected 0, got {b_sees}. A non-zero count means SessionId is cosmetic and every "
            f"statement is running on one shared auto-committing connection"
        )
    # Second independent observable of the same absence: a brand-new connection, no SessionId.
    fresh_sees = _count_fresh(rsd, cluster_id, table)
    assert fresh_sees == 0, (
        f"a brand-new connection must not see session A's uncommitted row either: expected 0, "
        f"got {fresh_sees}"
    )

    # ---- repair only the withheld thing: COMMIT ----
    _in_session(rsd, session_a, "COMMIT")

    b_after_commit = _count_in_session(rsd, session_b, table)
    assert b_after_commit == 1, (
        f"after session A COMMITs, session B's byte-identical count must now see the row: "
        f"expected 1, got {b_after_commit}. This is the positive control that makes the three "
        f"zeroes above evidence of isolation rather than of a write that never happened"
    )
    fresh_after_commit = _count_fresh(rsd, cluster_id, table)
    assert fresh_after_commit == 1, (
        f"and an independent connection must see it too: expected 1, got {fresh_after_commit}"
    )

    # ---- leg 2: ROLLBACK un-does a write that WAS visible to its own session ----
    _in_session(rsd, session_a, f"BEGIN; INSERT INTO {table} VALUES (2)")
    a_sees_two = _count_in_session(rsd, session_a, table)
    assert a_sees_two == 2, (
        f"inside the second transaction session A must see BOTH rows: expected 2, got {a_sees_two}"
    )
    b_still_one = _count_in_session(rsd, session_b, table)
    assert b_still_one == 1, (
        f"session B must still see only the COMMITTED row while the second transaction is open: "
        f"expected 1, got {b_still_one}"
    )
    _in_session(rsd, session_a, "ROLLBACK")
    a_after_rollback = _count_in_session(rsd, session_a, table)
    assert a_after_rollback == 1, (
        f"after ROLLBACK session A must no longer see its own withdrawn row: expected 1, got "
        f"{a_after_rollback}"
    )

    # Terminal assertion: an INDEPENDENT read at the destination, on a connection that took part
    # in none of the above, through the rows themselves rather than a count — exactly the one
    # committed value survives.
    submitted = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=ADMIN_USERNAME,
            Sql=f"SELECT id FROM {table} ORDER BY id",
        )
    )
    described = _wait_statement(rsd, submitted["Id"], timeout_s=_WARM_STATEMENT_DEADLINE_S)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the terminal read did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    final = [_cell(row, 0) for row in _rows_of(rsd, described["Id"])]
    assert final == [1], (
        f"exactly the COMMITTED row must survive: expected [1], got {final!r}. [1, 2] means the "
        f"ROLLBACK did nothing; [] means the COMMIT did nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
