"""partition-projection-bounds-the-scan-with-no-metastore-partitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partition-projection-bounds-the-scan-with-no-metastore-partitions"
GROUP = "query-execution"
SERVICES = ["athena"]

#: Three Hive partition prefixes on S3, of three DIFFERENT sizes so no two byte counts can
#: coincide — but only the first two fall inside the declared projection range. The third exists
#: on S3 and is deliberately UNREACHABLE: an engine that discovers partitions by listing prefixes
#: returns its rows, and an engine that honours the declared projection cannot.
_IN_RANGE = (
    ("2024-01-01", (1, 2)),
    ("2024-01-02", (3, 4, 5)),
)
_OUT_OF_RANGE = ("2024-01-09", (6, 7, 8, 9))
_RANGE = "2024-01-01,2024-01-02"



def _partition_body(values):
    """The CSV bytes for one partition, from the same tuple the expected values are computed from."""
    return "".join(f"{v}\n" for v in values).encode()


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location, so DeleteBucket alone would fail and a failed
    DeleteBucket is this service's most likely cost leak."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    # registered BEFORE the name is used anywhere else
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _start_query(athena, out, query_string, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=240, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline; RAISES on
    timeout so a truncated poll can never record a wrong oracle."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(
            QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state!r})")


def _run_sql(athena, out, sql, database=None):
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state!r}, expected 'SUCCEEDED': {sql!r} -- "
            f"{status.get('StateChangeReason')!r}")
    return qid


def _data_rows(athena, qid):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:]."""
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _all_rows(athena, qid):
    """Every row, header included. SHOW PARTITIONS emits no header row, so slicing rows[1:] would
    turn a one-partition answer into an empty one."""
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers)."""
    return f'"{database}"."{table}"'


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Partition projection computes partitions from table properties alone: SHOW PARTITIONS is
    empty, yet a projected-key predicate returns and scans exactly that prefix, the unpredicated
    scan reads exactly the two in-range prefixes, and an out-of-range prefix adds no rows or bytes."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    sizes = {}
    for date, values in _IN_RANGE + (_OUT_OF_RANGE,):
        body = _partition_body(values)
        s3.put_object(Bucket=data_bucket, Key=f"proj/dt={date}/rows.csv", Body=body)
        sizes[date] = len(body)
    # A FIXTURE guard, not an assertion about the target: the three partitions must have three
    # DISTINCT sizes, or a byte-count assertion below could pass against the wrong prefix.
    assert len(set(sizes.values())) == 3, (
        f"the three partitions must differ in size so no byte count can coincide, got {sizes!r}")

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-proj-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the table too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int) "
        "PARTITIONED BY (`dt` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/proj/' "
        "TBLPROPERTIES ("
        "'projection.enabled' = 'true', "
        "'projection.dt.type' = 'date', "
        f"'projection.dt.range' = '{_RANGE}', "
        "'projection.dt.format' = 'yyyy-MM-dd')")

    table_name = _dml_name(database, table)

    # --- leg 1: the catalogue holds NO partitions. No MSCK REPAIR, no ALTER ADD PARTITION has
    #     been issued above, so anything the queries below return came from the projection.
    show_qid = _run_sql(athena, out, f"SHOW PARTITIONS `{database}`.`{table}`")
    listed = _all_rows(athena, show_qid)
    assert listed == [], (
        f"a projection-only table registers no partitions in the catalogue, so SHOW PARTITIONS "
        f"must return nothing, got {listed!r}")

    # --- leg 2: a predicate on the projected key returns that prefix's rows and only its bytes ---
    first_date, first_values = _IN_RANGE[0]
    one_qid = _run_sql(
        athena, out,
        f"SELECT id FROM {table_name} WHERE dt = '{first_date}' ORDER BY id",
        database=database)
    one_rows = _data_rows(athena, one_qid)
    assert one_rows == [[str(v)] for v in sorted(first_values)], (
        f"WHERE dt = {first_date!r} must return exactly that prefix's rows in order: expected "
        f"{[[str(v)] for v in sorted(first_values)]!r}, got {one_rows!r}")
    one_scanned = _scanned(athena, one_qid)
    assert one_scanned == sizes[first_date], (
        f"the projected predicate must read exactly the {sizes[first_date]} bytes of "
        f"dt={first_date}/rows.csv, got DataScannedInBytes={one_scanned!r} (sizes {sizes!r})")

    # --- leg 3: the unpredicated scan reads the declared RANGE, not what S3 happens to hold ---
    in_range_rows = sum(len(v) for _, v in _IN_RANGE)
    in_range_bytes = sum(sizes[d] for d, _ in _IN_RANGE)
    all_qid = _run_sql(athena, out, f"SELECT count(*) FROM {table_name}", database=database)
    all_rows_out = _data_rows(athena, all_qid)
    assert all_rows_out == [[str(in_range_rows)]], (
        f"the unpredicated count must see only the {in_range_rows} rows in the projected range "
        f"{_RANGE!r}, not the {len(_OUT_OF_RANGE[1])} rows also sitting under "
        f"dt={_OUT_OF_RANGE[0]}, got {all_rows_out!r}")
    all_scanned = _scanned(athena, all_qid)
    assert all_scanned == in_range_bytes, (
        f"the unpredicated scan must read exactly the {in_range_bytes} bytes of the two in-range "
        f"prefixes and never open the {sizes[_OUT_OF_RANGE[0]]}-byte out-of-range object, got "
        f"DataScannedInBytes={all_scanned!r}")

    # --- leg 4: naming the out-of-range prefix explicitly still reads nothing. The object is
    #     there; the projection says it is not a partition, so the engine must not open it.
    out_date = _OUT_OF_RANGE[0]
    out_qid = _run_sql(
        athena, out,
        f"SELECT count(*) FROM {table_name} WHERE dt = '{out_date}'", database=database)
    out_rows = _data_rows(athena, out_qid)
    assert out_rows == [["0"]], (
        f"dt = {out_date!r} is outside the declared projection range {_RANGE!r}, so the count "
        f"must be 0 even though s3://{data_bucket}/proj/dt={out_date}/rows.csv exists with "
        f"{len(_OUT_OF_RANGE[1])} rows in it, got {out_rows!r}")
    out_scanned = _scanned(athena, out_qid)
    assert out_scanned == 0, (
        f"an out-of-range projected predicate must read ZERO bytes — the engine should not even "
        f"open the {sizes[out_date]}-byte object — got DataScannedInBytes={out_scanned!r}")

    # --- the invariant tying the legs together: the in-range prefixes account for the whole scan
    second_date, _ = _IN_RANGE[1]
    second_qid = _run_sql(
        athena, out,
        f"SELECT count(*) FROM {table_name} WHERE dt = '{second_date}'", database=database)
    second_scanned = _scanned(athena, second_qid)
    assert one_scanned + second_scanned == all_scanned, (
        f"the per-partition byte counts must sum to the whole-table count: {one_scanned!r} + "
        f"{second_scanned!r} != {all_scanned!r}")
    assert one_scanned < all_scanned, (
        f"no pruning happened: the predicated query read {one_scanned!r} bytes and the "
        f"unpredicated one read {all_scanned!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
