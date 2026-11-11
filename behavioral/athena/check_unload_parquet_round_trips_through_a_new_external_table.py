"""unload-parquet-round-trips-through-a-new-external-table."""
from __future__ import annotations

import time
import urllib.parse

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "unload-parquet-round-trips-through-a-new-external-table"
GROUP = 'query-execution'
SERVICES = ['athena']



def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`, `<qid>.txt` for
    DDL, and `<qid>-manifest.csv` for an UNLOAD) into the output location, so a bucket that only
    ever received our uploads is still non-empty at teardown. DeleteBucket on a non-empty bucket
    fails, and a failed DeleteBucket is the single most likely cost leak in this service — hence
    the paginated delete_objects sweep.
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
    # us-east-1 is CreateBucket's own default region and the one case where passing
    # LocationConstraint explicitly is rejected — not a pin to that region.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "unload-parquet-round-trips"},
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


def _data_rows(results):
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data rows are
    rows[1:]. Returned as a LIST, never a set — ORDER BY makes the order a server-side guarantee
    and an emulator that shuffles must fail."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _keys_under(s3, bucket, prefix):
    """Paginated listing of every key under a prefix."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _split_s3_uri(uri):
    """(bucket, key) from an s3:// URI, parsed with urllib rather than split on '/' by hand."""
    p = urllib.parse.urlparse(uri)
    assert p.scheme == "s3", f"not an s3 URI: {uri!r}"
    assert p.netloc, f"s3 URI has no bucket: {uri!r}"
    return p.netloc, p.path.lstrip("/")


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). A backtick inside a SELECT/UNLOAD makes the statement
    unclassifiable and StartQueryExecution refuses it synchronously with
    `InvalidRequestException: Queries of this type are not supported`."""
    return f'"{database}"."{table}"'


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """UNLOAD writes Parquet objects to S3 and lists exactly those keys in its `<qid>-manifest.csv`,
    GetQueryResults returns no rows for it, and a new `STORED AS PARQUET` external table over the
    destination reads the original rows back in order."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    results_bucket, results_prefix = _split_s3_uri(out)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker so the round-tripped values cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    src_csv = (f"1,alpha-{marker}\n2,bravo-{marker}\n3,charlie-{marker}\n").encode()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=src_csv)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    dst = ctx.unique_name("sim2real-behav-dst-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'",
    )

    # --- act: UNLOAD to a prefix that is unique per run (UNLOAD refuses a non-empty target) ---
    unload_prefix = "unloaded/"
    qid = _run_sql(
        athena, out,
        f"UNLOAD (SELECT id, name FROM {_dml_name(database, src)} ORDER BY id) "
        f"TO 's3://{data_bucket}/{unload_prefix}' WITH (format = 'PARQUET')",
        database=database,
    )

    # --- the engine really wrote data objects, and they really are Parquet ---
    data_keys = _keys_under(s3, data_bucket, unload_prefix)
    assert data_keys, (
        f"UNLOAD wrote no object under s3://{data_bucket}/{unload_prefix} — the statement "
        f"SUCCEEDED but produced nothing")
    for key in data_keys:
        head = s3.get_object(Bucket=data_bucket, Key=key, Range="bytes=0-3")["Body"].read()
        assert head == b"PAR1", (
            f"the object UNLOAD wrote at {key!r} is not Parquet: its first four bytes are "
            f"{head!r}, not the PAR1 magic")

    # --- the manifest names exactly those objects ---
    manifest_key = f"{results_prefix}{qid}-manifest.csv"
    manifest_body = s3.get_object(Bucket=results_bucket, Key=manifest_key)["Body"].read().decode()
    manifest_lines = [ln for ln in manifest_body.splitlines() if ln.strip()]
    assert manifest_lines, (
        f"UNLOAD must write a non-empty manifest at s3://{results_bucket}/{manifest_key}, "
        f"got {manifest_body!r}")
    manifest_pairs = sorted(_split_s3_uri(ln) for ln in manifest_lines)
    assert manifest_pairs == sorted((data_bucket, k) for k in data_keys), (
        f"the manifest must list exactly the objects UNLOAD wrote; it lists {manifest_pairs!r} "
        f"but S3 holds {[(data_bucket, k) for k in sorted(data_keys)]!r}")

    # --- an UNLOAD's result set is empty: the rows went to S3, not to the caller ---
    unload_rows = _data_rows(athena.get_query_results(QueryExecutionId=qid))
    assert unload_rows == [], (
        f"UNLOAD returns its data through S3, so GetQueryResults must carry no data rows, got "
        f"{unload_rows!r}")

    # --- read the Parquet back through a NEW external table: the round trip ---
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{dst}` (`id` int, `name` string) "
        f"STORED AS PARQUET LOCATION 's3://{data_bucket}/{unload_prefix}'",
    )
    reread = _run_sql(athena, out,
                      f"SELECT id, name FROM {_dml_name(database, dst)} ORDER BY id",
                      database=database)
    reread_rows = _data_rows(athena.get_query_results(QueryExecutionId=reread))
    assert reread_rows == [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"],
                           ["3", f"charlie-{marker}"]], (
        f"the Parquet round trip must return this run's exact rows in ORDER BY id order; the "
        f"marker was {marker!r} and the re-read gave {reread_rows!r}")
    reread_scanned = athena.get_query_execution(QueryExecutionId=reread)["QueryExecution"][
        "Statistics"]["DataScannedInBytes"]
    assert reread_scanned > 0, (
        f"re-reading the UNLOADed Parquet must scan real bytes, got "
        f"DataScannedInBytes={reread_scanned!r} — a fabricated ResultSet scans nothing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
