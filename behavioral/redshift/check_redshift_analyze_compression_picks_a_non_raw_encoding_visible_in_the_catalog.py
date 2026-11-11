"""redshift-analyze-compression-picks-a-non-raw-encoding-visible-in-the-catalog."""

from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-analyze-compression-picks-a-non-raw-encoding-visible-in-the-catalog"
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
# Teardown has 1800 s in all: the three DROP teardowns before it take up to 120 s each, with a
# margin for the rest, so the cluster delete and its wait for ClusterNotFound take what is left.
_DELETE_CLUSTER_DEADLINE_S = 1320
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


_SEED = "sim2real_behav_enc_seed"
_RAW = "sim2real_behav_enc_raw"
_ENCODED = "sim2real_behav_enc_chosen"
_ROW_TARGET = 20000
# Five distinct values over 20000 rows: compressibility that is not marginal, so a recommendation
# of RAW would be a real finding rather than a coin flip.
_DISTINCT = 5


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ANALYZE COMPRESSION samples the stored rows: on 20000 copies of five values it recommends a
    non-RAW encoding with a positive estimated reduction, and pg_table_def reports that encoding
    on a table created with it while the ENCODE RAW table reports none."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    scenario = "rs-encoding"
    cluster_id = ctx.unique_name("sim2real-behav-rs-encoding-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_SEED} (n INT)")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_SEED}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id, f"INSERT INTO {_SEED} VALUES " + ", ".join(
        f"({n})" for n in range(10)))

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_RAW} (v VARCHAR(64) ENCODE RAW)")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_RAW}",
                                         timeout_s=120))
    fill = (f"INSERT INTO {_RAW} SELECT 'sim2real-value-' || (a.n % {_DISTINCT})::VARCHAR "
            f"FROM {_SEED} a, {_SEED} b, {_SEED} c, {_SEED} d")
    _run_sql(rsd, cluster_id, fill)
    _run_sql(rsd, cluster_id, fill)

    raw_count = _select(rsd, cluster_id, f"SELECT count(*) FROM {_RAW}")
    assert raw_count == [[{"longValue": _ROW_TARGET}]], (
        f"the sample table must hold exactly {_ROW_TARGET} rows before ANALYZE COMPRESSION, got "
        f"{raw_count!r}"
    )
    distinct = _select(rsd, cluster_id, f"SELECT count(DISTINCT v) FROM {_RAW}")
    assert distinct == [[{"longValue": _DISTINCT}]], (
        f"the sample must be low-cardinality for the recommendation to be unambiguous, got "
        f"{distinct!r} distinct values"
    )

    # ANALYZE COMPRESSION returns a result set (Table, Column, Encoding, Est_reduction_pct).
    analyze_id = _run_sql(rsd, cluster_id, f"ANALYZE COMPRESSION {_RAW}", timeout_s=600)
    described = _wait_statement(rsd, analyze_id)
    assert described["HasResultSet"] is True, (
        f"{DATAPLANE_MARKER}: ANALYZE COMPRESSION must return its recommendation as a result set, "
        f"got HasResultSet={described.get('HasResultSet')!r}"
    )
    result = _retrying(lambda: rsd.get_statement_result(Id=analyze_id))
    columns = [c["name"] for c in result["ColumnMetadata"]]
    assert columns == ["Table", "Column", "Encoding", "Est_reduction_pct"], (
        f"ANALYZE COMPRESSION's result columns must name the recommendation, got {columns!r}"
    )
    recommendations = {_cell(r, 1).strip(): (_cell(r, 2).strip(), _cell(r, 3))
                       for r in result["Records"]}
    assert list(recommendations) == ["v"], (
        f"the recommendation must cover exactly the table's one column, got {recommendations!r}"
    )
    recommended, est_reduction = recommendations["v"]
    assert recommended not in ("raw", "none"), (
        f"ANALYZE COMPRESSION must recommend a real encoding for a {_ROW_TARGET}-row column over "
        f"{_DISTINCT} distinct values, got {recommended!r}"
    )
    assert float(est_reduction) > 0.0, (
        f"a non-RAW recommendation must come with a positive estimated reduction, got "
        f"{est_reduction!r} for {recommended!r}"
    )

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_ENCODED} (v VARCHAR(64) ENCODE {recommended})")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_ENCODED}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id, f"INSERT INTO {_ENCODED} SELECT v FROM {_RAW}", timeout_s=600)

    catalog = _select(rsd, cluster_id,
                      'SELECT tablename, "column", encoding FROM pg_table_def '
                      f"WHERE schemaname = 'public' AND tablename IN ('{_RAW}', '{_ENCODED}')")
    encodings = {_cell(r, 0): _cell(r, 2) for r in catalog}
    assert encodings.get(_ENCODED) == recommended, (
        f"pg_table_def must report the encoding the table was created with: ANALYZE recommended "
        f"{recommended!r}, the catalog says {encodings.get(_ENCODED)!r} ({encodings!r})"
    )
    assert encodings.get(_RAW) == "none", (
        f"an ENCODE RAW column is reported as 'none' by pg_table_def, got "
        f"{encodings.get(_RAW)!r} ({encodings!r})"
    )

    counts = _select(rsd, cluster_id,
                     f"SELECT (SELECT count(*) FROM {_RAW}), (SELECT count(*) FROM {_ENCODED})")
    assert [_cell(counts[0], 0), _cell(counts[0], 1)] == [_ROW_TARGET, _ROW_TARGET], (
        f"re-encoding must not change the row count, got {counts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
