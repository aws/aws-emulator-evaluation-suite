"""data-api-temporal-types-round-trip-and-the-engine-computes-their-span."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-temporal-types-round-trip-and-the-engine-computes-their-span"
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
_DELETE_CLUSTER_DEADLINE_S = 300
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120

_ROWS = 5
# Exact spacing between the rows' timestamps, so the aggregate the engine computes can be
# checked against a value derived independently in Python.
_SPAN_S = 7
_TZ_OFFSET = timedelta(hours=5, minutes=30)
_DEFAULT_NOTE = "sim2real"
_NUMERIC_PRECISION = 12
_NUMERIC_SCALE = 4


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
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


def _member(record, i):
    """The NAME of the union member a cell used — the type discriminator, which is the whole point
    of asserting on a Field rather than on its value."""
    field = record[i]
    assert len(field) == 1, (
        f"a Field is a UNION and must carry exactly one member, got {field!r} at column {i}"
    )
    return next(iter(field))


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


def _result(rsd, cluster_id, sql, timeout_s=_WARM_STATEMENT_DEADLINE_S):
    """(records, column_metadata) for a SELECT, paginated (GetStatementResult is token-paged)."""
    statement_id = _run_sql(rsd, cluster_id, sql, timeout_s=timeout_s)["Id"]
    records, columns, token = [], None, None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        resp = _retrying(lambda: rsd.get_statement_result(**kwargs))
        if columns is None:
            columns = resp["ColumnMetadata"]
        records.extend(resp.get("Records", []))
        token = resp.get("NextToken")
        if not token:
            break
    return records, columns


def _parse_instant(text, *, assume_utc):
    """The UTC instant a Redshift temporal string denotes. RAISES on a spelling it does not
    recognise, with the raw text, rather than guessing: a silent fallback would turn a format
    change into a passing check."""
    assert isinstance(text, str) and text, (
        f"a temporal column must come back as a non-empty string, got {text!r}"
    )
    candidate = text.strip().replace(" ", "T", 1)
    # Redshift renders a zone as '+00' where ISO-8601 wants '+00:00'.
    if len(candidate) > 3 and candidate[-3] in "+-" and candidate[-2:].isdigit():
        candidate = f"{candidate}:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise AssertionError(
            f"could not parse the temporal value {text!r} returned by Redshift: {exc}"
        ) from exc
    if parsed.tzinfo is None:
        assert assume_utc, (
            f"a TIMESTAMPTZ column must come back carrying a zone, got the naive value {text!r}"
        )
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Temporal values written from the live UTC clock survive the Data API round trip to the
    microsecond, a TIMESTAMPTZ written at +05:30 reads back as the same instant in UTC, and the
    engine's datediff and sum over those rows equal the values computed independently."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id for the caller, got {account!r}"
    )
    scenario = "rs-temporal"

    cluster_id = ctx.unique_name("sim2real-behav-rs-temporal-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    table = "sim2real_behav_temporal"
    _run_sql(
        rsd,
        cluster_id,
        f"CREATE TABLE {table} ("
        f"k INT, "
        f"ts TIMESTAMP, "
        f"tz TIMESTAMPTZ, "
        f"d DATE, "
        f"amt DECIMAL({_NUMERIC_PRECISION},{_NUMERIC_SCALE}), "
        f"note VARCHAR(24) DEFAULT '{_DEFAULT_NOTE}')",
    )
    ctx.on_cleanup(lambda: _drop_table(rsd, cluster_id, table))

    # Every value below is derived from the live clock, with a non-zero microsecond component so a
    # target that truncates to the second is caught. `- timedelta(days=1)` keeps the DATE column
    # away from a midnight rollover between writing and reading.
    base = datetime.now(timezone.utc).replace(microsecond=123_456) - timedelta(days=1)
    instants = [base + timedelta(seconds=_SPAN_S * n) for n in range(_ROWS)]
    amounts = [
        (Decimal(instant.microsecond + n * 1_000) / (10 ** _NUMERIC_SCALE)).quantize(
            Decimal(1).scaleb(-_NUMERIC_SCALE)
        )
        for n, instant in enumerate(instants)
    ]

    values = ", ".join(
        # tz is written in a NON-UTC zone on purpose: the same instant, spelled +05:30.
        f"({n}, '{_sql_ts(instant)}', '{_sql_ts(instant + _TZ_OFFSET)}+05:30', "
        f"'{instant.date().isoformat()}', {amounts[n]})"
        for n, instant in enumerate(instants)
    )
    _run_sql(
        rsd,
        cluster_id,
        f"INSERT INTO {table} (k, ts, tz, d, amt) VALUES {values}",
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
    )

    records, columns = _result(
        rsd, cluster_id, f"SELECT k, ts, tz, d, amt, note FROM {table} ORDER BY k"
    )
    assert len(records) == _ROWS, (
        f"the SELECT must return the {_ROWS} inserted rows, got {len(records)}"
    )

    # ---- the Field union's type discriminators ----
    first = records[0]
    members = [_member(first, i) for i in range(6)]
    assert members == [
        "longValue", "stringValue", "stringValue", "stringValue", "stringValue", "stringValue"
    ], (
        f"the Field discriminators must be: int -> longValue, and TIMESTAMP / TIMESTAMPTZ / DATE / "
        f"DECIMAL / VARCHAR all -> stringValue, because Redshift will not render any of them as a "
        f"lossy JSON number; got {members!r}"
    )

    # ---- microsecond fidelity, and UTC normalisation of the zone-aware column ----
    for n, record in enumerate(records):
        assert _cell(record, 0) == n, (
            f"row {n} must come back in k order, got k={_cell(record, 0)!r}"
        )
        expected = instants[n]
        raw_ts = _cell(record, 1)
        got_ts = _parse_instant(raw_ts, assume_utc=True)
        assert got_ts == expected, (
            f"row {n}: the TIMESTAMP must survive to the MICROSECOND: wrote "
            f"{_sql_ts(expected)!r}, read back {raw_ts!r} which is {got_ts.isoformat()}, expected "
            f"{expected.isoformat()}"
        )
        raw_tz = _cell(record, 2)
        got_tz = _parse_instant(raw_tz, assume_utc=False)
        assert got_tz == expected, (
            f"row {n}: the TIMESTAMPTZ was written as the same instant spelled +05:30 and must "
            f"come back as that instant: read {raw_tz!r} which is {got_tz.isoformat()}, expected "
            f"{expected.isoformat()}"
        )
        assert raw_tz != raw_ts, (
            f"row {n}: the TIMESTAMPTZ rendering must differ from the naive TIMESTAMP rendering — "
            f"one carries a zone and the other does not — but both read {raw_tz!r}"
        )
        assert _cell(record, 3) == expected.date().isoformat(), (
            f"row {n}: a DATE must come back as the bare calendar date with no time part: "
            f"expected {expected.date().isoformat()!r}, got {_cell(record, 3)!r}"
        )
        assert _cell(record, 4) == str(amounts[n]), (
            f"row {n}: a DECIMAL({_NUMERIC_PRECISION},{_NUMERIC_SCALE}) must come back as its "
            f"exact digit string INCLUDING trailing zeros: expected {str(amounts[n])!r}, got "
            f"{_cell(record, 4)!r}"
        )
        assert _cell(record, 5) == _DEFAULT_NOTE, (
            f"row {n}: the column DEFAULT must have been applied by the engine, since the INSERT "
            f"never named `note`: expected {_DEFAULT_NOTE!r}, got {_cell(record, 5)!r}"
        )

    # ---- ColumnMetadata: the fields an emulator drops ----
    assert [c["typeName"] for c in columns] == [
        "int4", "timestamp", "timestamptz", "date", "numeric", "varchar"
    ], f"unexpected ColumnMetadata typeNames {[c.get('typeName') for c in columns]!r}"
    numeric_meta = columns[4]
    assert (numeric_meta.get("precision"), numeric_meta.get("scale")) == (
        _NUMERIC_PRECISION,
        _NUMERIC_SCALE,
    ), (
        f"a DECIMAL({_NUMERIC_PRECISION},{_NUMERIC_SCALE}) must report BOTH its precision and its "
        f"SCALE — scale is the member an emulator leaves at 0 — got precision="
        f"{numeric_meta.get('precision')!r} scale={numeric_meta.get('scale')!r}"
    )
    # `scale` is not a DECIMAL-only property. TIMESTAMP and TIMESTAMPTZ
    # report the fractional-seconds precision (6, microseconds) as their scale, matching the
    # DECIMAL column's digit-count semantics rather than reading as 0 like every other type.
    assert [c.get("scale") for c in columns] == [0, 6, 6, 0, _NUMERIC_SCALE, 0], (
        f"scale must be 0 for int4/date/varchar, 6 (microsecond fractional-seconds precision) for "
        f"TIMESTAMP/TIMESTAMPTZ, and {_NUMERIC_SCALE} for the DECIMAL column; got "
        f"{[c.get('scale') for c in columns]!r}"
    )
    assert [c.get("tableName") for c in columns] == [table] * 6, (
        f"every column of a single-table SELECT must report that table in ColumnMetadata.tableName "
        f"— unasserted in every shipped redshift artifact — got "
        f"{[c.get('tableName') for c in columns]!r}"
    )
    assert [c.get("schemaName") for c in columns] == ["public"] * 6, (
        f"every column must report its schema in ColumnMetadata.schemaName, got "
        f"{[c.get('schemaName') for c in columns]!r}"
    )

    # ---- the catalogue's independent view of the same columns, via a DIFFERENT operation ----
    described = _retrying(
        lambda: rsd.describe_table(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME,
            Schema="public", Table=table,
        )
    )
    catalogue = {c["name"]: c for c in described["ColumnList"]}
    assert sorted(catalogue) == ["amt", "d", "k", "note", "ts", "tz"], (
        f"DescribeTable must report all six columns, got {sorted(catalogue)!r}"
    )
    assert (catalogue["amt"].get("precision"), catalogue["amt"].get("scale")) == (
        _NUMERIC_PRECISION,
        _NUMERIC_SCALE,
    ), (
        f"the catalogue and the query result must AGREE on the DECIMAL's precision and scale; "
        f"DescribeTable said precision={catalogue['amt'].get('precision')!r} "
        f"scale={catalogue['amt'].get('scale')!r}"
    )
    note_default = catalogue["note"].get("columnDefault")
    assert note_default and _DEFAULT_NOTE in note_default, (
        f"DescribeTable must report the declared DEFAULT for `note` in columnDefault — a member "
        f"asserted in NO shipped redshift artifact — and it must contain the literal "
        f"{_DEFAULT_NOTE!r}; got {note_default!r}"
    )
    assert catalogue["k"].get("columnDefault") in (None, ""), (
        f"a column with no DEFAULT must not report one, got "
        f"{catalogue['k'].get('columnDefault')!r} for `k`"
    )

    # ---- terminal assertion: the ENGINE computes values derived independently in Python ----
    aggregate, _ = _result(
        rsd,
        cluster_id,
        f"SELECT datediff(microsecond, min(ts), max(ts)), datediff(second, min(ts), max(ts)), "
        f"sum(amt), count(*) FROM {table}",
    )
    assert len(aggregate) == 1, f"an aggregate must return exactly one row, got {aggregate!r}"
    expected_us = int((instants[-1] - instants[0]) / timedelta(microseconds=1))
    expected_sum = sum(amounts, Decimal(0)).quantize(Decimal(1).scaleb(-_NUMERIC_SCALE))
    assert _cell(aggregate[0], 0) == expected_us, (
        f"the engine must compute the microsecond span over the rows it stored: expected "
        f"{expected_us}, got {_cell(aggregate[0], 0)!r}. A mismatch that is an exact multiple of "
        f"1_000_000 means the microseconds were truncated on the way in"
    )
    assert _cell(aggregate[0], 1) == _SPAN_S * (_ROWS - 1), (
        f"and the second span: expected {_SPAN_S * (_ROWS - 1)}, got {_cell(aggregate[0], 1)!r}"
    )
    assert Decimal(str(_cell(aggregate[0], 2))) == expected_sum, (
        f"the engine must sum the DECIMAL column exactly: expected {expected_sum}, got "
        f"{_cell(aggregate[0], 2)!r}"
    )
    assert _cell(aggregate[0], 3) == _ROWS, (
        f"the aggregate must have seen all {_ROWS} rows, got {_cell(aggregate[0], 3)!r}"
    )


def _sql_ts(instant):
    """A Redshift timestamp literal with an explicit microsecond component, zone-free. The zone is
    appended by the caller for the TIMESTAMPTZ column."""
    return instant.strftime("%Y-%m-%d %H:%M:%S.%f")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
