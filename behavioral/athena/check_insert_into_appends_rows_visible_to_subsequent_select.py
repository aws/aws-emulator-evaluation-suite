"""insert-into-appends-rows-visible-to-subsequent-select."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "insert-into-appends-rows-visible-to-subsequent-select"
GROUP = 'query-execution'
SERVICES = ['athena']



def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`, `<qid>.txt` for
    DDL) into the output location, and INSERT INTO writes a fresh data object per statement, so a
    bucket that only ever received our uploads is still non-empty at teardown. DeleteBucket on a
    non-empty bucket fails, and a failed DeleteBucket is the single most likely cost leak in this
    service — hence the paginated delete_objects sweep.
    """
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "insert-into-appends-rows-visible-to-subsequent-select"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None, **extra):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    kwargs.update(extra)
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None, workgroup=None, **extra):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup, **extra)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}"
        )
    return qid


def _stats(athena, qid):
    return athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Statistics"]


def _data_rows(results):
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data rows are
    rows[1:]. Returned as a LIST, never a set — ORDER BY makes the order a server-side guarantee
    and an emulator that shuffles must fail."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _keys_under(s3, bucket, prefix):
    """PAGINATED listing of a prefix. An INSERT-heavy table
    accumulates one object per statement, so a single-page list_objects_v2 is not a bound."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). A backtick inside a SELECT/INSERT makes the statement
    unclassifiable and StartQueryExecution refuses it synchronously with `InvalidRequestException:
    Queries of this type are not supported`."""
    return f'"{database}"."{table}"'


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """INSERT INTO a Parquet table APPENDS: each statement adds one new data object to the table's
    S3 location without replacing the previous one, and a later SELECT returns the union of all
    inserted rows in ORDER BY order, each carrying the run's marker."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker, so the rows read back cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=b"1,seed\n")

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    tbl = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'",
    )

    # An Athena-MANAGED table is required: INSERT INTO cannot write to a plain CSV external
    # table. `WHERE 1 = 0` gives the right schema with no data, so the object count starts at 0.
    table_prefix = "inserted/"
    _run_sql(
        athena, out,
        f"CREATE TABLE {_dml_name(database, tbl)} WITH (format = 'PARQUET', "
        f"external_location = 's3://{data_bucket}/{table_prefix}') AS "
        f"SELECT id, name FROM {_dml_name(database, src)} WHERE 1 = 0",
        database=database,
    )
    keys_empty = _keys_under(s3, data_bucket, table_prefix)
    assert keys_empty == [], (
        f"a CTAS projecting zero rows must create the table without writing a data object, "
        f"found {keys_empty!r}")

    # --- first INSERT: two rows, one new object ---
    ins1 = _run_sql(
        athena, out,
        f"INSERT INTO {_dml_name(database, tbl)} VALUES "
        f"(1, 'alpha-{marker}'), (2, 'bravo-{marker}')",
        database=database,
    )
    assert athena.get_query_execution(QueryExecutionId=ins1)["QueryExecution"][
        "StatementType"] == "DML", (
        "INSERT INTO is a DML statement; got "
        f"{athena.get_query_execution(QueryExecutionId=ins1)['QueryExecution']['StatementType']!r}")
    keys_1 = _keys_under(s3, data_bucket, table_prefix)
    assert len(keys_1) == 1, (
        f"the first INSERT must write exactly one data object under {table_prefix!r}, "
        f"found {keys_1!r}")

    # --- second INSERT: appends, so the first object must SURVIVE ---
    _run_sql(athena, out,
             f"INSERT INTO {_dml_name(database, tbl)} VALUES (3, 'charlie-{marker}')",
             database=database)
    keys_2 = _keys_under(s3, data_bucket, table_prefix)
    assert len(keys_2) == 2, (
        f"the second INSERT must write a SECOND data object, not overwrite the first: "
        f"{keys_1!r} -> {keys_2!r}")
    assert keys_1[0] in keys_2, (
        f"INSERT INTO must APPEND — the first statement's object {keys_1[0]!r} was replaced; "
        f"the location now holds {keys_2!r}")

    # --- the union is readable back out of the Parquet the engine wrote ---
    sel = _run_sql(athena, out,
                   f"SELECT id, name FROM {_dml_name(database, tbl)} ORDER BY id",
                   database=database)
    rows = _data_rows(athena.get_query_results(QueryExecutionId=sel))
    assert rows == [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"],
                    ["3", f"charlie-{marker}"]], (
        f"the SELECT must return both INSERTs' rows in ORDER BY id order with this run's marker "
        f"{marker!r}, got {rows!r}")
    scanned = _stats(athena, sel)["DataScannedInBytes"]
    assert scanned > 0, (
        f"reading back {len(keys_2)} Parquet objects must scan real bytes, got "
        f"DataScannedInBytes={scanned!r} — a fabricated ResultSet scans nothing")

    # --- and the source table is untouched: INSERT wrote to the target only ---
    src_rows = _data_rows(athena.get_query_results(QueryExecutionId=_run_sql(
        athena, out, f"SELECT id, name FROM {_dml_name(database, src)} ORDER BY id",
        database=database)))
    assert src_rows == [["1", "seed"]], (
        f"INSERT INTO the target must not touch the source table, which still holds its one "
        f"seed row; got {src_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
