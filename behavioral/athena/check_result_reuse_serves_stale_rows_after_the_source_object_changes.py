"""result-reuse-serves-stale-rows-after-the-source-object-changes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "result-reuse-serves-stale-rows-after-the-source-object-changes"
GROUP = "query-execution"
SERVICES = ["athena"]

_REUSE_MINUTES = 60


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket; Athena writes result files into the output location."""
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
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
    """Poll GetQueryExecution to a terminal state; raise on timeout."""
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


def _run_sql(athena, out, sql, database=None, **extra):
    qid = _start_query(athena, out, sql, database=database, **extra)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _data_rows(results):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:]."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML goes through the Trino parser (double-quoted identifiers); DDL through Hive
    (backticks). A backtick inside a SELECT is refused synchronously by StartQueryExecution."""
    return f'"{database}"."{table}"'


def _execute(athena, out, sql, database, reuse_enabled):
    """Run `sql` with reuse on or off; return (rows, reused_flag, data_scanned_bytes)."""
    reuse = {"ResultReuseByAgeConfiguration": {"Enabled": bool(reuse_enabled)}}
    if reuse_enabled:
        reuse["ResultReuseByAgeConfiguration"]["MaxAgeInMinutes"] = _REUSE_MINUTES
    qid = _run_sql(athena, out, sql, database=database, ResultReuseConfiguration=reuse)
    stats = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Statistics"]
    rows = _data_rows(athena.get_query_results(QueryExecutionId=qid))
    return rows, stats["ResultReuseInformation"]["ReusedPreviousResult"], \
        stats["DataScannedInBytes"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After the source object is overwritten, a reuse-on rerun returns the OLD rows and scans 0
    bytes; the same SQL with reuse off returns the NEW rows and scans the new object's byte count.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/reusing-query-results.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    marker = ctx.unique_name("").replace("-", "")[:12]
    # Deliberately different lengths as well as different content, so the byte counts cannot
    # coincide and a stale row set cannot be confused with a fresh one.
    body_v1 = f"1,before-{marker}\n".encode()
    body_v2 = f"1,after-{marker}\n2,after2-{marker}\n3,after3-{marker}\n".encode()
    assert len(body_v1) != len(body_v2), (
        f"the two payloads must differ in length for the cost assertions to be separable: "
        f"{len(body_v1)} vs {len(body_v2)}")
    key = "src/rows.csv"
    s3.put_object(Bucket=data_bucket, Key=key, Body=body_v1)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    sql = f"SELECT name FROM {_dml_name(database, table)} ORDER BY name"
    rows_v1 = [[f"before-{marker}"]]
    rows_v2 = [[f"after-{marker}"], [f"after2-{marker}"], [f"after3-{marker}"]]

    first_rows, first_reused, first_bytes = _execute(athena, out, sql, database, True)
    assert first_reused is False, (
        f"the first execution has nothing to reuse, so ReusedPreviousResult must be False, got "
        f"{first_reused!r}")
    assert first_rows == rows_v1, (
        f"the seeding execution must return the v1 row (marker {marker!r}): expected {rows_v1!r}, "
        f"got {first_rows!r}")
    assert first_bytes == len(body_v1), (
        f"the seeding execution must have read exactly the {len(body_v1)} v1 bytes, got "
        f"DataScannedInBytes={first_bytes!r}")

    s3.put_object(Bucket=data_bucket, Key=key, Body=body_v2)
    landed = s3.get_object(Bucket=data_bucket, Key=key)["Body"].read()
    assert landed == body_v2, (
        f"the overwrite must be observably in place before anything is concluded from it: "
        f"s3://{data_bucket}/{key} holds {landed!r}, expected {body_v2!r}")

    # Must run before any reuse-off execution of the same SQL: any successful execution rewrites
    # the cache entry, whatever its own Enabled flag. Up to 3 sequential attempts because reuse
    # does not always engage on the first rerun.
    reused_seen = False
    attempts = []
    for attempt in range(3):
        rows, reused, scanned = _execute(athena, out, sql, database, True)
        attempts.append((reused, scanned, rows))
        if reused:
            reused_seen = True
            assert scanned == 0, (
                f"attempt {attempt} reports ReusedPreviousResult=True, so it read a cached result "
                f"and DataScannedInBytes must be exactly 0, got {scanned!r}")
            assert rows == rows_v1, (
                f"attempt {attempt} reused the cached result, so it must serve the PRE-change rows "
                f"{rows_v1!r} even though the object now holds {rows_v2!r}; got {rows!r}")
            break
        assert scanned == len(body_v2), (
            f"attempt {attempt} reports ReusedPreviousResult=False, so it re-scanned the object "
            f"and must report exactly the {len(body_v2)} v2 bytes, got {scanned!r}")
        assert rows == rows_v2, (
            f"attempt {attempt} did not reuse, so it must return the current rows {rows_v2!r}, "
            f"got {rows!r}")
    assert reused_seen, (
        f"an identical rerun inside a {_REUSE_MINUTES}-minute reuse window must reuse the earlier "
        f"result at least once in 3 sequential attempts, else ResultReuseConfiguration is not "
        f"honoured at all; attempts were {attempts!r}")

    # Positive control, run last: an earlier reuse-off run would refresh the cache entry above.
    fresh_rows, fresh_reused, fresh_bytes = _execute(athena, out, sql, database, False)
    assert fresh_reused is False, (
        f"with ResultReuseByAgeConfiguration.Enabled=False the execution must be fresh, so "
        f"ReusedPreviousResult must be False, got {fresh_reused!r}")
    assert fresh_rows == rows_v2, (
        f"a fresh execution must see the overwritten object's three rows: expected {rows_v2!r}, "
        f"got {fresh_rows!r}")
    assert fresh_bytes == len(body_v2), (
        f"a fresh execution must read exactly the {len(body_v2)} v2 bytes, got "
        f"DataScannedInBytes={fresh_bytes!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
