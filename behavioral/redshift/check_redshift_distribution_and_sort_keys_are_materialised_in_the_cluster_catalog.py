"""redshift-distribution-and-sort-keys-are-materialised-in-the-cluster-catalog."""

from __future__ import annotations

import datetime
import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-distribution-and-sort-keys-are-materialised-in-the-cluster-catalog"
GROUP = 'sql-data-plane'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Marks a data-plane failure: the control plane accepted the statement but the engine did
# not do the work.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# Teardown has 1800 s in all: the five DROP teardowns before it take up to 120 s each, with a
# margin for the rest, so the cluster delete and its wait for ClusterNotFound take what is left.
_DELETE_CLUSTER_DEADLINE_S = 1080
_CLUSTER_DEADLINE_S = 900
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420

_REDSHIFT_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "redshift.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


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
    """CreateCluster with a bounded retry on the IAM-role races: a role created seconds ago is
    not yet visible to the Redshift control plane, which rejects the association outright rather
    than converging."""
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
    """Cost-leak teardown. SkipFinalClusterSnapshot=True so no snapshot blocks the delete and
    none is left billing; a cluster still 'creating' refuses deletion, so that is retried, and the
    delete is asynchronous, so the wait for ClusterNotFound follows. One deadline bounds both."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
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
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _submit(rsd, cluster_id, sql):
    return _retrying(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql))["Id"]


def _describe_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, return the DescribeStatement WITHOUT asserting."""
    return _wait_statement(rsd, _submit(rsd, cluster_id, sql), timeout_s=timeout_s)


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    statement_id = _submit(rsd, cluster_id, sql)
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql):
    """Every row of a SELECT's result, paginated (GetStatementResult is token-paged)."""
    statement_id = _run_sql(rsd, cluster_id, sql)
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


_SEED10 = "sim2real_behav_dist_seed10"
_SEED5 = "sim2real_behav_dist_seed5"
_SRC = "sim2real_behav_dist_src"
_KEYED = "sim2real_behav_dist_keyed"
_ALLDIST = "sim2real_behav_dist_all"
_ROWS = 5000
_BASE = datetime.datetime(2026, 1, 1, 0, 0, 0)
# The range the aggregate covers, as a closed interval on the sort column.
_FROM_ID, _TO_ID = 600, 1200


def _amount(row_id):
    return (row_id * 7) % 1000


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CTAS declaring DISTKEY(id) SORTKEY(ts) reports diststyle KEY(id) with ts as sortkey 1 in
    the catalog, a DISTSTYLE ALL table reports ALL, and a range aggregate over the sorted column
    equals the client's own arithmetic."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    scenario = "rs-distkey"
    cluster_id = ctx.unique_name("sim2real-behav-rs-distkey-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    for table, values in ((_SEED10, range(10)), (_SEED5, range(5))):
        _run_sql(rsd, cluster_id, f"CREATE TABLE {table} (n INT)")
        ctx.on_cleanup(lambda t=table: _describe_sql(
            rsd, cluster_id, f"DROP TABLE IF EXISTS {t}", timeout_s=120))
        _run_sql(rsd, cluster_id, f"INSERT INTO {table} VALUES " + ", ".join(
            f"({n})" for n in values))

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_SRC} (id INT, ts TIMESTAMP, amount INT)")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_SRC}",
                                         timeout_s=120))
    # id = 500a + 50b + 5c + d is a bijection from the cross join onto 0..4999.
    _run_sql(rsd, cluster_id,
             f"INSERT INTO {_SRC} SELECT (a.n * 500 + b.n * 50 + c.n * 5 + d.n) AS id, "
             f"TIMESTAMP '{_BASE:%Y-%m-%d %H:%M:%S}' + "
             f"((a.n * 500 + b.n * 50 + c.n * 5 + d.n) * INTERVAL '1 second'), "
             f"((a.n * 500 + b.n * 50 + c.n * 5 + d.n) * 7) % 1000 "
             f"FROM {_SEED10} a, {_SEED10} b, {_SEED10} c, {_SEED5} d",
             timeout_s=600)
    src_count = _select(rsd, cluster_id, f"SELECT count(*), count(DISTINCT id) FROM {_SRC}")
    assert [_cell(src_count[0], 0), _cell(src_count[0], 1)] == [_ROWS, _ROWS], (
        f"the source table must hold {_ROWS} rows with {_ROWS} distinct ids, got {src_count!r}"
    )

    _run_sql(rsd, cluster_id,
             f"CREATE TABLE {_KEYED} DISTKEY(id) SORTKEY(ts) AS SELECT id, ts, amount FROM {_SRC}",
             timeout_s=600)
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_KEYED}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id,
             f"CREATE TABLE {_ALLDIST} DISTSTYLE ALL AS SELECT id, ts, amount FROM {_SRC}",
             timeout_s=600)
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_ALLDIST}",
                                         timeout_s=120))

    info = _select(rsd, cluster_id,
                   'SELECT "table", diststyle, sortkey1 FROM svv_table_info '
                   f"WHERE \"table\" IN ('{_KEYED}', '{_ALLDIST}')")
    by_table = {_cell(r, 0): (_cell(r, 1), _cell(r, 2)) for r in info}
    assert sorted(by_table) == sorted([_ALLDIST, _KEYED]), (
        f"svv_table_info must account for both tables, got {by_table!r}"
    )
    assert by_table[_KEYED][0] == "KEY(id)", (
        f"a DISTKEY(id) table must report diststyle KEY(id), got {by_table[_KEYED]!r}"
    )
    assert by_table[_ALLDIST][0] == "ALL", (
        f"a DISTSTYLE ALL table must report diststyle ALL, got {by_table[_ALLDIST]!r}"
    )
    assert by_table[_KEYED][1] == "ts", (
        f"the keyed table's first sort column must be ts, got {by_table[_KEYED]!r}"
    )

    catalog = _select(rsd, cluster_id,
                      'SELECT "column", distkey, sortkey FROM pg_table_def '
                      f"WHERE schemaname = 'public' AND tablename = '{_KEYED}'")
    layout = {_cell(r, 0): (_cell(r, 1), _cell(r, 2)) for r in catalog}
    assert layout == {"id": (True, 0), "ts": (False, 1), "amount": (False, 0)}, (
        f"pg_table_def must materialise DISTKEY(id) SORTKEY(ts) as distkey on id and sortkey "
        f"ordinal 1 on ts, with amount unkeyed; got {layout!r}"
    )

    expected_sum = sum(_amount(i) for i in range(_FROM_ID, _TO_ID + 1))
    expected_count = _TO_ID - _FROM_ID + 1
    lower = _BASE + datetime.timedelta(seconds=_FROM_ID)
    upper = _BASE + datetime.timedelta(seconds=_TO_ID)
    aggregate = _select(rsd, cluster_id,
                        f"SELECT sum(amount), count(*) FROM {_KEYED} WHERE ts BETWEEN "
                        f"TIMESTAMP '{lower:%Y-%m-%d %H:%M:%S}' AND "
                        f"TIMESTAMP '{upper:%Y-%m-%d %H:%M:%S}'")
    observed = [_cell(aggregate[0], 0), _cell(aggregate[0], 1)]
    assert observed == [expected_sum, expected_count], (
        f"{DATAPLANE_MARKER}: the cluster computed {observed!r} over the sorted range, the client "
        f"computed {[expected_sum, expected_count]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
