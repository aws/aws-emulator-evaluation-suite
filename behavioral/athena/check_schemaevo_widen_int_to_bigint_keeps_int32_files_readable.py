"""schemaevo-widen-int-to-bigint-keeps-int32-files-readable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schemaevo-widen-int-to-bigint-keeps-int32-files-readable"
GROUP = "schema-evolution"
SERVICES = ["athena"]

#: int32's own ceiling, so the pre-widening values are the widest the narrow physical type can
#: hold — a truncating reader cannot coincidentally return the right answer for this one.
_INT32_MAX = 2147483647
#: Beyond int32 by design: only a genuinely 64-bit column can return this at all.
_BEYOND_INT32 = 9000000000


def _empty_and_delete_bucket(s3, bucket):
    """Empty then delete a bucket; Athena writes its own result artifacts into it."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's own default region and the one case where passing
    # LocationConstraint explicitly is rejected — not a pin to that region.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
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


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline."""
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
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None):
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _result(athena, qid):
    """((name, type) per column, data rows) for a SELECT, fully paginated.

    Only the first page repeats the column names as row 0. Rows stay a list: ORDER BY fixes order.
    """
    cols, rows, first = None, [], True
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        rs = page["ResultSet"]
        if cols is None:
            cols = [(c["Name"], c["Type"]) for c in rs["ResultSetMetadata"]["ColumnInfo"]]
        page_rows = [[d.get("VarCharValue") for d in r["Data"]] for r in rs["Rows"]]
        if first:
            page_rows, first = page_rows[1:], False
        rows.extend(page_rows)
    return cols, rows


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). A backtick inside a SELECT makes the statement unclassifiable and
    StartQueryExecution refuses it synchronously."""
    return f'"{database}"."{table}"'


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix in a bucket this check created, paginated and sorted."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


def _stage_parquet(athena, s3, out, database, bucket, select_sql, generation, lake_prefix):
    """UNLOAD one generation of Parquet and copy it under the table's LOCATION; return its keys.

    UNLOAD refuses a non-empty destination, so each generation is staged in its own prefix.
    """
    stage_prefix = f"stage-{generation}/"
    _run_sql(athena, out,
             f"UNLOAD ({select_sql}) TO 's3://{bucket}/{stage_prefix}' "
             "WITH (format = 'PARQUET')", database=database)
    staged = _keys_under(s3, bucket, stage_prefix)
    assert staged, (
        f"UNLOAD wrote no object under s3://{bucket}/{stage_prefix} for generation "
        f"{generation!r} — the statement SUCCEEDED but produced nothing")
    landed = []
    for i, key in enumerate(staged):
        dest = f"{lake_prefix}{generation}-{i}"
        s3.copy_object(Bucket=bucket, Key=dest, CopySource={"Bucket": bucket, "Key": key})
        head = s3.get_object(Bucket=bucket, Key=dest, Range="bytes=0-3")["Body"].read()
        assert head == b"PAR1", (
            f"generation {generation!r} must be real Parquet under the table location; the first "
            f"four bytes of {dest!r} are {head!r}, not the PAR1 magic")
        landed.append(dest)
    return landed


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """Widening `int` to `bigint` re-reads existing INT32 Parquet unchanged (including int32 max),
    reports `bigint` without rewriting any object, and a later INT64 file reads beside the INT32
    files so one `max()` spans both widths.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker, so the rows that come back cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(
        Bucket=data_bucket, Key="src/rows.csv",
        Body=f"7,narrow-{marker}\n{_INT32_MAX},max32-{marker}\n".encode())

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    lake = ctx.unique_name("sim2real-behav-lake-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops every table, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    # Generation 1 is written from an `int` column, so its physical Parquet type is INT32.
    lake_prefix = "lake/"
    _stage_parquet(
        athena, s3, out, database, data_bucket,
        f"SELECT id, name FROM {_dml_name(database, src)} ORDER BY id", "i32", lake_prefix)
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{lake}` (`id` int, `name` string) "
        f"STORED AS PARQUET LOCATION 's3://{data_bucket}/{lake_prefix}'")

    narrow = [["7", f"narrow-{marker}"], [str(_INT32_MAX), f"max32-{marker}"]]
    base_qid = _run_sql(athena, out,
                        f"SELECT id, name FROM {_dml_name(database, lake)} ORDER BY id",
                        database=database)
    base_cols, base_rows = _result(athena, base_qid)
    assert base_cols == [("id", "integer"), ("name", "varchar")], (
        f"the pre-widening table must report its column as `integer`, got {base_cols!r}")
    assert base_rows == narrow, (
        f"the pre-widening read must return this run's exact rows in ORDER BY id order; the marker "
        f"was {marker!r} and the read gave {base_rows!r}")

    # REPLACE COLUMNS is catalogue-only: the 32-bit files on S3 are not rewritten.
    before = _keys_under(s3, data_bucket, lake_prefix)
    _run_sql(
        athena, out,
        f"ALTER TABLE `{database}`.`{lake}` REPLACE COLUMNS (`id` bigint, `name` string)")
    after = _keys_under(s3, data_bucket, lake_prefix)
    assert after == before, (
        f"widening is a catalogue-only change and must not rewrite, add or remove a single object "
        f"under s3://{data_bucket}/{lake_prefix}: it held {before!r} and now holds {after!r}")

    widened_qid = _run_sql(athena, out,
                           f"SELECT id, name FROM {_dml_name(database, lake)} ORDER BY id",
                           database=database)
    widened_cols, widened_rows = _result(athena, widened_qid)
    assert widened_cols == [("id", "bigint"), ("name", "varchar")], (
        f"after REPLACE COLUMNS the result set must declare the widened type, got "
        f"{widened_cols!r}")
    assert widened_rows == narrow, (
        f"widening must re-interpret the already-written INT32 values EXACTLY — including int32's "
        f"own ceiling {_INT32_MAX} — got {widened_rows!r}, expected {narrow!r}")
    widened_scanned = _scanned(athena, widened_qid)
    assert widened_scanned > 0, (
        f"the post-widening read must scan the real Parquet files, got "
        f"DataScannedInBytes={widened_scanned!r} — a result set answered from the catalogue alone "
        f"scans nothing")

    _stage_parquet(
        athena, s3, out, database, data_bucket,
        f"SELECT CAST({_BEYOND_INT32} AS bigint) id, 'wide-{marker}' name", "i64", lake_prefix)
    mixed_qid = _run_sql(athena, out,
                         f"SELECT id, name FROM {_dml_name(database, lake)} ORDER BY id",
                         database=database)
    mixed_cols, mixed_rows = _result(athena, mixed_qid)
    assert mixed_cols == widened_cols, (
        f"landing an INT64 file must not change the resolved schema, which the catalogue owns: it "
        f"was {widened_cols!r} and is now {mixed_cols!r}")
    assert mixed_rows == narrow + [[str(_BEYOND_INT32), f"wide-{marker}"]], (
        f"the widened column must read INT32 and INT64 files in one scan, so the 32-bit rows and "
        f"the 64-bit row all appear in ORDER BY id order; got {mixed_rows!r}")

    agg_qid = _run_sql(
        athena, out,
        f"SELECT max(id) AS biggest, count(*) AS total FROM {_dml_name(database, lake)}",
        database=database)
    _, agg_rows = _result(athena, agg_qid)
    assert agg_rows == [[str(_BEYOND_INT32), "3"]], (
        f"an aggregate over the widened column must span both physical widths and return "
        f"{_BEYOND_INT32} over 3 rows — a 32-bit column cannot hold that value at all — got "
        f"{agg_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
