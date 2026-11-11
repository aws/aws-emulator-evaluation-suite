"""columnar-projection-reads-a-fraction-of-the-row-format-bytes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "columnar-projection-reads-a-fraction-of-the-row-format-bytes"
GROUP = "query-execution"
SERVICES = ["athena"]

#: 4000 rows of one narrow bigint and one wide fixed string. The width asymmetry is the point:
#: the padding column carries 200/202 of every row's bytes, so an engine that really reads only
#: the requested column chunk reports a byte count two orders of magnitude below the row-format
#: one, while an engine that re-reads the whole object cannot.
_N = 4000
_PAD = "W" * 200



def _dataset():
    """The CSV bytes and the Python-computed oracle for every aggregate asserted below."""
    body = "".join(f"{i},{_PAD}\n" for i in range(_N)).encode()
    return body, sum(range(_N))


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location and this check writes a CTAS Parquet object into the data
    bucket, so DeleteBucket alone would fail and a failed DeleteBucket is this service's most
    likely cost leak."""
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


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers)."""
    return f'"{database}"."{table}"'


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


def _bytes_under(s3, bucket, prefix):
    """Total size of every object under a prefix THIS CHECK wrote, paginated. Scoped to a bucket
    this check created, so the total is a property of the query and not of the account."""
    total = 0
    count = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            total += obj["Size"]
            count += 1
    return total, count


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The engine performs column projection on Parquet: the same aggregate scans an order of
    magnitude less than over the TEXTFILE source, count(*) over Parquet scans zero bytes, and the
    bytes for two columns read separately sum exactly to the bytes for both together."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, expected_sum = _dataset()
    s3.put_object(Bucket=data_bucket, Key="text/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    text_tbl = ctx.unique_name("sim2real-behav-txt-").replace("-", "_")
    parq_tbl = ctx.unique_name("sim2real-behav-parq-").replace("-", "_")
    parq_prefix = "parquet/"
    # Registered BEFORE the CREATE it undoes: CASCADE drops the tables too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{text_tbl}` (`n` bigint, `pad` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/text/'")

    text_name = _dml_name(database, text_tbl)
    parq_name = _dml_name(database, parq_tbl)

    # --- baseline: a row-oriented layout cannot project, so it reads the whole object ---
    text_qid = _run_sql(athena, out, f"SELECT sum(n) FROM {text_name}", database=database)
    text_rows = _data_rows(athena, text_qid)
    assert text_rows == [[str(expected_sum)]], (
        f"sum(n) over the TEXTFILE table must equal the Python-computed sum of 0..{_N - 1} "
        f"({expected_sum}), got {text_rows!r}")
    text_scanned = _scanned(athena, text_qid)
    assert text_scanned == len(body), (
        f"a row-format scan must read every byte of the {len(body)}-byte object this check "
        f"uploaded, got DataScannedInBytes={text_scanned!r}")

    # --- materialise the same rows in a columnar layout ---
    _run_sql(
        athena, out,
        f"CREATE TABLE {parq_name} WITH (format = 'PARQUET', "
        f"external_location = 's3://{data_bucket}/{parq_prefix}') AS "
        f"SELECT n, pad FROM {text_name}",
        database=database)
    parq_bytes, parq_objects = _bytes_under(s3, data_bucket, parq_prefix)
    assert parq_objects >= 1 and parq_bytes > 0, (
        f"the CTAS must have written at least one non-empty Parquet object under "
        f"s3://{data_bucket}/{parq_prefix}, got {parq_objects!r} objects / {parq_bytes!r} bytes")

    # --- leg 1: the narrow column alone, over the columnar copy ---
    narrow_qid = _run_sql(athena, out, f"SELECT sum(n) FROM {parq_name}", database=database)
    narrow_rows = _data_rows(athena, narrow_qid)
    assert narrow_rows == [[str(expected_sum)]], (
        f"sum(n) over the Parquet copy must equal the same Python-computed sum ({expected_sum}), "
        f"got {narrow_rows!r}")
    narrow_scanned = _scanned(athena, narrow_qid)
    assert 0 < narrow_scanned < parq_bytes, (
        f"projecting `n` must read some but NOT all of the {parq_bytes}-byte Parquet object, got "
        f"DataScannedInBytes={narrow_scanned!r}")
    # The invariant the check exists for: same question, same rows, columnar layout, far cheaper.
    assert narrow_scanned * 10 < text_scanned, (
        f"the columnar read must cost at least an order of magnitude less than the identical "
        f"row-format read: {narrow_scanned!r} vs {text_scanned!r} bytes for the same sum(n) over "
        f"the same {_N} rows")

    # --- leg 2: the wide column alone, and both together: the byte counts must be ADDITIVE ---
    wide_qid = _run_sql(athena, out, f"SELECT max(pad) FROM {parq_name}", database=database)
    wide_rows = _data_rows(athena, wide_qid)
    assert wide_rows == [[_PAD]], (
        f"max(pad) must return the {len(_PAD)}-character padding string every row carries, got "
        f"{[[(c[:16] + '...' if c and len(c) > 16 else c) for c in r] for r in wide_rows]!r}")
    wide_scanned = _scanned(athena, wide_qid)
    assert wide_scanned > 0, (
        f"projecting `pad` must read the column's chunk, got DataScannedInBytes={wide_scanned!r}")

    both_qid = _run_sql(
        athena, out, f"SELECT sum(n), max(pad) FROM {parq_name}", database=database)
    both_rows = _data_rows(athena, both_qid)
    assert both_rows == [[str(expected_sum), _PAD]], (
        f"selecting both aggregates must return both computed values in order, got "
        f"{[[c[:12] for c in r] for r in both_rows]!r}")
    both_scanned = _scanned(athena, both_qid)
    assert both_scanned == narrow_scanned + wide_scanned, (
        f"per-column reads must be additive — reading both columns must cost exactly the sum of "
        f"reading each ({narrow_scanned} + {wide_scanned} = "
        f"{narrow_scanned + wide_scanned}), got {both_scanned!r}")
    assert both_scanned < parq_bytes, (
        f"even reading both columns must cost less than the whole {parq_bytes}-byte object "
        f"(the footer and page indexes are not row data), got {both_scanned!r}")

    # --- leg 3: count(*) needs no column at all, so it must read ZERO bytes ---
    count_qid = _run_sql(athena, out, f"SELECT count(*) FROM {parq_name}", database=database)
    count_rows = _data_rows(athena, count_qid)
    assert count_rows == [[str(_N)]], (
        f"count(*) over the Parquet copy must be exactly {_N}, got {count_rows!r}")
    count_scanned = _scanned(athena, count_qid)
    assert count_scanned == 0, (
        f"count(*) over a columnar table is answerable from the footer row count, so it must "
        f"scan ZERO data bytes, got DataScannedInBytes={count_scanned!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
