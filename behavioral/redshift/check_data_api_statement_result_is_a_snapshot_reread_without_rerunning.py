"""data-api-statement-result-is-a-snapshot-reread-without-rerunning."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-statement-result-is-a-snapshot-reread-without-rerunning"
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

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
_CLUSTER_DEADLINE_S = 900
# Teardown has 1800 s in all: the DROP teardown before it takes up to 120 s, with a margin for the
# rest, so the cluster delete and its wait for ClusterNotFound take what is left.
_DELETE_CLUSTER_DEADLINE_S = 1500
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120
_REREADS = 3


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
    """Cost-leak teardown: retry a wrong-state refusal, then wait for ClusterNotFound, under one
    deadline. Anything OTHER than not-found / wrong-state / throttle RAISES."""
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


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the DescribeStatement."""
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return described


def _snapshot(rsd, statement_id):
    """The whole stored result of a finished statement, as a comparable tuple: the row values, the
    reported total, and the column metadata. Paginated (GetStatementResult is token-paged)."""
    rows, columns, total, token = [], None, None, None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        resp = _retrying(lambda: rsd.get_statement_result(**kwargs))
        if columns is None:
            columns = resp["ColumnMetadata"]
            total = resp.get("TotalNumRows")
        rows.extend(_cell(record, 0) for record in resp.get("Records", []))
        token = resp.get("NextToken")
        if not token:
            break
    return (tuple(rows), total, tuple(sorted((c["name"], c["typeName"]) for c in columns)))


def _statement_ids(rsd, cluster_id):
    """Every statement id ListStatements reports for this cluster. The cluster is created by this
    check and used by nothing else, so the population is exactly what ran here."""
    ids, token = set(), None
    while True:
        kwargs = {"ClusterIdentifier": cluster_id, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = _retrying(lambda: rsd.list_statements(**kwargs))
        ids.update(s["Id"] for s in resp.get("Statements", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


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


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A finished statement's result is a stored snapshot: re-reading its id returns the original
    rows after the source rows change and the table is dropped, while a new statement sees the
    change; the re-reads create no statement and move no DescribeStatement timestamp."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id for the caller, got {account!r}"
    )
    scenario = "rs-result-snapshot"

    cluster_id = ctx.unique_name("sim2real-behav-rs-snapshot-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_snapshot"
    _run_sql(rsd, cluster_id, f"CREATE TABLE {table} (id INT)")
    ctx.on_cleanup(lambda: _drop_table(rsd, cluster_id, table))
    _run_sql(
        rsd, cluster_id, f"INSERT INTO {table} VALUES (1), (2), (3)",
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
    )

    select = f"SELECT id FROM {table} ORDER BY id"
    subject = _run_sql(rsd, cluster_id, select, timeout_s=_WARM_STATEMENT_DEADLINE_S)
    subject_id = subject["Id"]
    original = _snapshot(rsd, subject_id)
    assert original[0] == (1, 2, 3), (
        f"the statement must first read the three seeded rows, got {original[0]!r}"
    )
    assert original[1] == 3, f"TotalNumRows must be 3, got {original[1]!r}"

    ids_before = _statement_ids(rsd, cluster_id)
    assert subject_id in ids_before, (
        f"ListStatements must report the statement under test {subject_id!r}; it reported "
        f"{sorted(ids_before)!r}"
    )

    # ---- change the database underneath the finished statement ----
    insert4 = _run_sql(
        rsd, cluster_id, f"INSERT INTO {table} VALUES (4)", timeout_s=_WARM_STATEMENT_DEADLINE_S
    )
    delete1 = _run_sql(
        rsd, cluster_id, f"DELETE FROM {table} WHERE id = 1",
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
    )

    # Positive control on the same wiring, in the same instant: a NEW statement running the
    # IDENTICAL SQL must see the change. Without this, "the old statement still returns [1, 2, 3]"
    # cannot be told apart from "the mutations never happened".
    moved = _run_sql(rsd, cluster_id, select, timeout_s=_WARM_STATEMENT_DEADLINE_S)
    assert moved["Id"] != subject_id, (
        f"re-submitting the same SQL must mint a NEW statement id, got {subject_id!r} again"
    )
    assert _snapshot(rsd, moved["Id"])[0] == (2, 3, 4), (
        f"a new statement over the mutated table must see the mutation: expected (2, 3, 4), got "
        f"{_snapshot(rsd, moved['Id'])[0]!r}. Without this the snapshot legs prove nothing"
    )

    # ---- freeze detector: the OLD statement's result is exactly unchanged, three times ----
    for attempt in range(_REREADS):
        again = _snapshot(rsd, subject_id)
        assert again == original, (
            f"re-read {attempt + 1} of {_REREADS}: a finished statement's result is a stored "
            f"SNAPSHOT and must be EXACTLY what it was — rows, TotalNumRows and ColumnMetadata — "
            f"even though the table now reads (2, 3, 4). Expected {original!r}, got {again!r}. "
            f"Getting (2, 3, 4) here means the target re-executed the SQL on read"
        )

    # Second channel of the same freeze assertion: reads create no statements and move no
    # timestamps. The mutation statements themselves (the INSERT and DELETE run to change the
    # table underneath the subject) also mint ids and belong in the expected set: ListStatements
    # lists them alongside the subject.
    mutation_ids = {insert4["Id"], delete1["Id"], moved["Id"]}
    ids_after = _statement_ids(rsd, cluster_id)
    assert ids_after == ids_before | mutation_ids, (
        f"the only statements added since the first listing are the two mutations and the "
        f"positive control {sorted(mutation_ids)!r}; {_REREADS} GetStatementResult calls must add "
        f"none. Expected {sorted(ids_before | mutation_ids)!r}, got {sorted(ids_after)!r}"
    )
    redescribed = _retrying(lambda: rsd.describe_statement(Id=subject_id))
    assert (
        redescribed["Status"],
        redescribed.get("UpdatedAt"),
        redescribed.get("ResultRows"),
    ) == (subject["Status"], subject.get("UpdatedAt"), subject.get("ResultRows")), (
        f"reading a result must not advance the statement record: expected (Status, UpdatedAt, "
        f"ResultRows) == ({subject['Status']!r}, {subject.get('UpdatedAt')!r}, "
        f"{subject.get('ResultRows')!r}), got ({redescribed.get('Status')!r}, "
        f"{redescribed.get('UpdatedAt')!r}, {redescribed.get('ResultRows')!r})"
    )

    # ---- terminal assertion: the snapshot outlives its own source table ----
    _run_sql(rsd, cluster_id, f"DROP TABLE {table}", timeout_s=_WARM_STATEMENT_DEADLINE_S)
    gone = _retrying(
        lambda: rsd.describe_table(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME,
            Schema="public", Table=table,
        )
    )
    assert gone.get("ColumnList") == [], (
        f"the source table must really be gone: DescribeTable must report an EMPTY ColumnList, got "
        f"{gone.get('ColumnList')!r}"
    )
    orphaned = _snapshot(rsd, subject_id)
    assert orphaned == original, (
        f"the stored result must survive the table it came from being DROPPED — this is the leg a "
        f"target that re-executes on read cannot pass at all, because there is nothing left to "
        f"execute against. Expected {original!r}, got {orphaned!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
