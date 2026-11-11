"""data-api-batch-execute-statement-substatement-ordering."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-batch-execute-statement-substatement-ordering"
GROUP = 'data-plane'
SERVICES = ['redshift']


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


def _client_error(fn):
    """Call *fn* and return the AWS error it raises; a success fails the check."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call succeeded where AWS rejects it")


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
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# Redshift provisioning is minutes-scale; _wait_until returns the instant the cluster is available.
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
    """Cheapest shape: ONE node, no public endpoint (the Data API needs neither a security
    group nor public accessibility), 1-day snapshot retention."""
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
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
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


# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _wait_for_cluster_gone(rs, cluster_id, deadline):
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
            raise TimeoutError(f"cluster {cluster_id} still listed ({status!r}) at the teardown deadline")
        time.sleep(2)


def _delete_cluster(rs, cluster_id):
    """Teardown: DeleteCluster without a final snapshot, retrying InvalidClusterState every 2 s, then
    wait for ClusterNotFound, since the delete is asynchronous. One deadline bounds both."""
    deadline = time.monotonic() + _TEARDOWN_S
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
    _wait_for_cluster_gone(rs, cluster_id, deadline)


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} did not FINISH: status={described['Status']!r} error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql):
    """Run a SELECT and return its Records (rows), in the order the engine returned them."""
    statement_id = _run_sql(rsd, cluster_id, sql)
    return _retrying(lambda: rsd.get_statement_result(Id=statement_id))["Records"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement runs its Sqls in submitted order (statement 3 reads the row
    statement 2 wrote) and reports one SubStatement per input as "<batch-id>:<n>", 1-indexed;
    DescribeStatement on an address narrows the parent to that position, out-of-range ones do not resolve."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-behav-rs-batch-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_batch_order"
    sqls = [
        f"CREATE TABLE {table} (id INT, val VARCHAR(16))",
        f"INSERT INTO {table} VALUES (1, 'first')",
        # Depends on statement 2 having already committed: out-of-order execution inserts
        # nothing here instead of failing, which is exactly the silent bug being caught.
        f"INSERT INTO {table} SELECT id + 1, 'second' FROM {table} WHERE val = 'first'",
    ]
    submitted = _retrying(
        lambda: rsd.batch_execute_statement(
            ClusterIdentifier=cluster_id,
            Database=DB_NAME,
            DbUser=ADMIN_USERNAME,
            Sqls=sqls,
            StatementName="sim2real-behav-batch-order",
        )
    )
    batch_id = submitted["Id"]
    assert batch_id, f"BatchExecuteStatement returned no Id: {submitted}"
    assert submitted["ClusterIdentifier"] == cluster_id, submitted

    described = _wait_statement(rsd, batch_id)
    assert described["Status"] == "FINISHED", (
        f"batch did not FINISH: {described.get('Status')!r} error={described.get('Error')!r}"
    )

    subs = described["SubStatements"]
    assert len(subs) == len(sqls), (
        f"expected one SubStatement per submitted SQL ({len(sqls)}), got {len(subs)}"
    )
    assert [s["QueryString"] for s in subs] == sqls, (
        "SubStatements must preserve submission ORDER (a list, not a set); got "
        f"{[s.get('QueryString') for s in subs]}"
    )
    assert [s["Id"] for s in subs] == [f"{batch_id}:{n}" for n in range(1, len(sqls) + 1)], (
        f"sub-statement ids must be the 1-indexed '<batch-id>:<n>' form, got {[s.get('Id') for s in subs]}"
    )
    assert [s["Status"] for s in subs] == ["FINISHED"] * len(sqls), (
        f"every sub-statement of a FINISHED batch must be FINISHED, got {[s.get('Status') for s in subs]}"
    )
    assert all(s["HasResultSet"] is False for s in subs), (
        f"DDL/DML sub-statements must report HasResultSet=False, got {[s.get('HasResultSet') for s in subs]}"
    )

    rows = _select(rsd, cluster_id, f"SELECT id, val FROM {table} ORDER BY id")
    assert rows == [
        [{"longValue": 1}, {"stringValue": "first"}],
        [{"longValue": 2}, {"stringValue": "second"}],
    ], (
        "the batch must have executed in order, leaving exactly the two dependent rows; got "
        f"{rows!r}"
    )

    # DescribeStatement on "<batch-id>:<n>" returns the PARENT batch record (bare batch Id, no
    # QueryString) whose SubStatements list is narrowed to exactly the addressed position.
    second = _retrying(lambda: rsd.describe_statement(Id=f"{batch_id}:2"))
    assert second["Status"] == "FINISHED", second
    assert second["Id"] == batch_id, (
        f"describing a sub-statement id must report the parent batch id {batch_id!r} (the ':n' "
        f"suffix is an address, not an identity), got {second.get('Id')!r}"
    )
    assert "QueryString" not in second, (
        f"a batch record has no single QueryString; got {second.get('QueryString')!r}"
    )
    narrowed = second["SubStatements"]
    assert len(narrowed) == 1, (
        f"describing position 2 must narrow SubStatements to that one position, got "
        f"{[s.get('Id') for s in narrowed]}"
    )
    assert narrowed[0]["Id"] == f"{batch_id}:2", (
        f"the narrowed SubStatement must be position 2, got {narrowed[0].get('Id')!r}"
    )
    assert narrowed[0]["QueryString"] == sqls[1], (
        f"sub-statement 2 must be the second submitted SQL, got {narrowed[0].get('QueryString')!r}"
    )

    # The addresses are 1-indexed and bounded: one past the end is not a statement at all.
    # Both ":0" and ":4" (for a 3-SQL batch) return ResourceNotFoundException "Query does
    # not exist." -- an emulator that clamps an out-of-range position to the first or last
    # sub-statement, or that treats the suffix as free-form, fails here.
    out_of_range = _client_error(lambda: rsd.describe_statement(Id=f"{batch_id}:{len(sqls) + 1}"))
    assert out_of_range["Code"] == "ResourceNotFoundException", (
        f"position {len(sqls) + 1} of a {len(sqls)}-statement batch must not resolve; "
        f"DescribeStatement returned {out_of_range}"
    )
    assert out_of_range["Message"] == "Query does not exist.", out_of_range
    zeroth = _client_error(lambda: rsd.describe_statement(Id=f"{batch_id}:0"))
    assert zeroth["Code"] == "ResourceNotFoundException", (
        f"sub-statement ids are 1-indexed, so position 0 must not resolve; got {zeroth}"
    )
    assert zeroth["Message"] == "Query does not exist.", zeroth

    _run_sql(rsd, cluster_id, f"DROP TABLE {table}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
