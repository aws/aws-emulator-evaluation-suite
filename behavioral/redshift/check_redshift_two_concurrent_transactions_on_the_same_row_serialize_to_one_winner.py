"""redshift-two-concurrent-transactions-on-the-same-row-serialize-to-one-winner."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-two-concurrent-transactions-on-the-same-row-serialize-to-one-winner"
GROUP = 'concurrency'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Marks a failure where the control plane accepted SQL the engine never ran, so it reads as a
# fidelity failure rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling, which is not a behavioral observation."""
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s, interval_s, what="condition", ctx=None):
    """Poll *probe* until *done* or timeout_s elapses (capped by the run's budget when *ctx* is
    given)."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# A single-node dc2.large reaches `available` in ~60-90 s; the deadline leaves headroom.
_CLUSTER_DEADLINE_S = 900
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# The first Data API statement against a freshly-available cluster includes connection
# establishment, so the statement deadline is deliberately larger than a warm query's.
_STATEMENT_DEADLINE_S = 420


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
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
    """Cheapest single-node, non-public cluster (the Data API needs no public endpoint);
    1-day snapshot retention because RA3 refuses 0."""
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
    """CreateCluster with a bounded retry: a just-created IAM role is not yet visible to
    Redshift, which rejects the association rather than converging."""
    deadline = time.monotonic() + 180
    while True:
        try:
            return _retrying(lambda: rs.create_cluster(**_cluster_params(rs, cluster_id,
                                                                        **overrides)))
        except ClientError as exc:
            if _code_of(exc) not in ("InvalidIamRoleFault", "InvalidClusterState",
                                     "AccessDenied") or time.monotonic() >= deadline:
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


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S, ctx=None):
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
        interval_s=2,
        what=f"cluster {cluster_id} to reach a terminal creation state",
        ctx=ctx,
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """Delete without a final snapshot, retrying in a bounded window because a cluster still
    'creating' refuses deletion."""
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


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    """Poll DescribeStatement to a TERMINAL status (SUBMITTED/PICKED/STARTED are transient)."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=1,
        what=f"statement {statement_id} to reach a terminal status",
        ctx=ctx,
    )


def _submit(rsd, cluster_id, sql):
    return _retrying(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql))["Id"]


def _describe_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, return the DescribeStatement WITHOUT asserting."""
    return _wait_statement(rsd, _submit(rsd, cluster_id, sql), timeout_s=timeout_s)


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the statement id."""
    statement_id = _submit(rsd, cluster_id, sql)
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s, ctx=ctx)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql, ctx=None):
    """Every row of a SELECT's result, paginated (GetStatementResult is token-paged)."""
    statement_id = _run_sql(rsd, cluster_id, sql, ctx=ctx)
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


def _cell(record, i):
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


def _submit_batch(rsd, cluster_id, sqls):
    """BatchExecuteStatement runs the array serially in ONE transaction, the only Data API
    path to a multi-statement transaction; it returns once submitted, before the batch runs."""
    return _retrying(lambda: rsd.batch_execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sqls=sqls))["Id"]


_TABLE = "sim2real_behav_contend"
_SEED = "sim2real_behav_contend_seed"
_FILLER = "sim2real_behav_contend_filler"
_WRITERS = ("alpha", "bravo")
# Redshift has no pg_sleep ("function PG_SLEEP does not exist"), so the window in which the two
# transactions overlap is widened with repeated real work.
_WIDENERS = 4


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent increments of one row under serializable isolation: at least one commits,
    the counter equals the commit count (no lost update), the value is a committer's, and any
    refused transaction failed with serializable-isolation error 1023.
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    scenario = "rs-contend"
    cluster_id = ctx.unique_name("sim2real-behav-rs-contend-")
    # Registered before creation: a leaked provisioned cluster is expensive.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id, ctx=ctx)

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_TABLE} (id INT, n INT, v VARCHAR(16))", ctx=ctx)
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_TABLE}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id, f"INSERT INTO {_TABLE} VALUES (1, 0, 'seed')", ctx=ctx)
    seeded = _select(rsd, cluster_id, f"SELECT n, v FROM {_TABLE} WHERE id = 1", ctx=ctx)
    assert [(_cell(r, 0), _cell(r, 1)) for r in seeded] == [(0, "seed")], (
        f"setup did not leave exactly the one seeded row: {seeded!r}"
    )

    # A thousand rows of filler, only so each transaction has a few hundred milliseconds of real
    # work to do between opening and committing.
    _run_sql(rsd, cluster_id, f"CREATE TABLE {_SEED} (n INT)", ctx=ctx)
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_SEED}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id, f"INSERT INTO {_SEED} VALUES " + ", ".join(
        f"({n})" for n in range(10)), ctx=ctx)
    _run_sql(rsd, cluster_id, f"CREATE TABLE {_FILLER} (n INT)", ctx=ctx)
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_FILLER}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id,
             f"INSERT INTO {_FILLER} SELECT a.n * 100 + b.n * 10 + c.n "
             f"FROM {_SEED} a, {_SEED} b, {_SEED} c", ctx=ctx)

    widener = f"SELECT count(*) FROM {_FILLER} a, {_FILLER} b"

    def _contend(value):
        # Textbook lost update: read, work, then write a value derived from the snapshot read.
        # Serializable isolation must not let both commit a stale-derived value.
        return _submit_batch(rsd, cluster_id, [
            f"SELECT n FROM {_TABLE} WHERE id = 1",
            *([widener] * _WIDENERS),
            f"UPDATE {_TABLE} SET n = (SELECT max(n) FROM {_TABLE}) + 1, v = '{value}' "
            f"WHERE id = 1",
        ])

    # Both batches are submitted back to back before either is polled, so they start together.
    batch_ids = {value: _contend(value) for value in _WRITERS}
    outcomes = {value: _wait_statement(rsd, batch_id, ctx=ctx) for value, batch_id in batch_ids.items()}

    statuses = {value: outcome["Status"] for value, outcome in outcomes.items()}
    errors = {value: outcome.get("Error") for value, outcome in outcomes.items()}
    committed = sorted(v for v, s in statuses.items() if s == "FINISHED")
    refused = sorted(v for v, s in statuses.items() if s in ("FAILED", "ABORTED"))
    assert len(committed) + len(refused) == len(_WRITERS), (
        f"every transaction must reach a terminal decision, got {statuses!r}"
    )
    assert committed, (
        f"{DATAPLANE_MARKER}: at least one of two contending transactions must commit, both were "
        f"refused: {statuses!r} {errors!r}"
    )

    final = _select(rsd, cluster_id, f"SELECT n, v FROM {_TABLE} WHERE id = 1", ctx=ctx)
    assert len(final) == 1, (
        f"concurrent updates to one row must leave exactly one row, got {final!r}"
    )
    final_n, final_v = _cell(final[0], 0), _cell(final[0], 1)

    # Each committed transaction applied its increment once; each refused one applied none.
    assert final_n == len(committed), (
        f"the counter must equal the number of committed transactions: {len(committed)} of "
        f"{len(_WRITERS)} committed ({committed!r}, refused {refused!r}) but the row holds n="
        f"{final_n!r}. Lower than that is a LOST UPDATE (a stale read blended the two writers); "
        f"higher means a rolled-back transaction's write survived."
    )
    assert final_v in committed, (
        f"the surviving value must belong to a transaction that COMMITTED; the row holds "
        f"{final_v!r} and the committed writers were {committed!r} (refused {refused!r})"
    )

    total = _select(rsd, cluster_id, f"SELECT count(*) FROM {_TABLE}", ctx=ctx)
    assert total == [[{"longValue": 1}]], (
        f"contending UPDATEs must not change the row count, got {total!r}"
    )

    # Serializing by aborting is as correct as by queueing, but the abort must be error 1023.
    for value in refused:
        error = errors[value] or ""
        assert "1023" in error, (
            f"transaction {value!r} did not commit, so its failure must be the "
            f"serializable-isolation violation (Redshift error 1023); got {error!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
