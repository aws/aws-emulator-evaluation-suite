"""schemaevo-narrowing-past-a-stored-value-fails-instead-of-truncating."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schemaevo-narrowing-past-a-stored-value-fails-instead-of-truncating"
GROUP = "schema-evolution"
SERVICES = ["athena"]

#: Hive's `tinyint` is a signed 8-bit column: 127 is its ceiling. Both arms of this check store
#: the same two in-range values; only the spilling arm also stores one above the ceiling, so the
#: declaration being narrowed to is IDENTICAL and the stored magnitude is the single difference.
_IN_RANGE = (7, 100)
_OVER_TINYINT = 300


# ===== helpers =====


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, including Athena's own query artifacts, before DeleteBucket,
    which fails on a non-empty bucket."""
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


def _terminal_status(athena, out, sql, database=None):
    """(query id, terminal state, Status envelope) for a statement EXPECTED to fail.
    The rejection is asynchronous, so the caller asserts on the state rather than an exception."""
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
    return qid, state, status


def _result(athena, qid):
    """((name, type) per column, data rows) for a SELECT, fully paginated.
    Only the first page repeats the column names as row 0. Rows stay a list: ORDER BY fixes order."""
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


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). A backtick inside a SELECT makes the statement unclassifiable and
    StartQueryExecution refuses it synchronously."""
    return f'"{database}"."{table}"'


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix THIS CHECK created, paginated. Scoped to a bucket this check made
    and a prefix only it writes, so "exactly these" is a property of the query."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


def _error(fn):
    """The AWS error (code, message) raised by `fn`; an unexpected success fails hard."""
    try:
        fn()
    except Exception as exc:  # botocore ClientError and its service-specific subclasses
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if not code:
            raise AssertionError(
                f"expected a service error carrying an error code, got {exc!r}") from exc
        return code, getattr(exc, "response", {}).get("Error", {}).get("Message")
    raise AssertionError(
        "GetQueryResults SUCCEEDED for a query that reached FAILED — the rows it returned are "
        "exactly the silently-wrong answer this check exists to forbid")


def _stage_parquet(athena, s3, out, database, bucket, select_sql, generation, lake_prefix):
    """Write one generation of real Parquet via UNLOAD under a table's LOCATION; return its keys.
    UNLOAD refuses a non-empty destination, so each generation is staged then copied."""
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """Narrowing a column type below a stored Parquet value fails the read with HIVE_CURSOR_ERROR
    and GetQueryResults returns no rows; the same narrowing over in-range values succeeds.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/types-of-updates.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker, so the rows that come back cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    lo, mid = _IN_RANGE
    s3.put_object(
        Bucket=data_bucket, Key="src/rows.csv",
        Body=(f"{lo},low-{marker}\n{mid},mid-{marker}\n"
              f"{_OVER_TINYINT},over-{marker}\n").encode())

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    fits = ctx.unique_name("sim2real-behav-fits-").replace("-", "_")
    spills = ctx.unique_name("sim2real-behav-spills-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops every table, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    # Two tables, same physical INT32 column type, differing ONLY in whether one stored value
    # exceeds the type they are both about to be narrowed to.
    src_name = _dml_name(database, src)
    arms = ((fits, "fits", f"SELECT id, name FROM {src_name} WHERE id <= {mid} ORDER BY id"),
            (spills, "spills", f"SELECT id, name FROM {src_name} ORDER BY id"))
    for table, label, select_sql in arms:
        prefix = f"{label}/"
        _stage_parquet(athena, s3, out, database, data_bucket, select_sql, label, prefix)
        _run_sql(
            athena, out,
            f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
            f"STORED AS PARQUET LOCATION 's3://{data_bucket}/{prefix}'")

    fits_rows = [[str(lo), f"low-{marker}"], [str(mid), f"mid-{marker}"]]
    spills_rows = fits_rows + [[str(_OVER_TINYINT), f"over-{marker}"]]

    # --- positive context: at full width BOTH tables read their own rows exactly ---
    for table, expected in ((fits, fits_rows), (spills, spills_rows)):
        qid = _run_sql(athena, out,
                       f"SELECT id, name FROM {_dml_name(database, table)} ORDER BY id",
                       database=database)
        cols, rows = _result(athena, qid)
        assert cols == [("id", "integer"), ("name", "varchar")], (
            f"{table}: the pre-narrowing table must report its column as `integer`, got {cols!r}")
        assert rows == expected, (
            f"{table}: the pre-narrowing read must return this run's exact rows in ORDER BY id "
            f"order; the marker was {marker!r} and the read gave {rows!r}")

    # --- break exactly ONE thing: narrow the declaration to tinyint on BOTH tables ---
    # REPLACE COLUMNS itself succeeds; the narrowing is enforced only at read time.
    keys_before = _keys_under(s3, data_bucket, "spills/")
    for table in (fits, spills):
        _run_sql(
            athena, out,
            f"ALTER TABLE `{database}`.`{table}` REPLACE COLUMNS (`id` tinyint, `name` string)")

    bad_qid, bad_state, bad_status = _terminal_status(
        athena, out, f"SELECT id, name FROM {_dml_name(database, spills)} ORDER BY id",
        database=database)
    assert bad_state == "FAILED", (
        f"reading a stored {_OVER_TINYINT} through a tinyint declaration must reach FAILED rather "
        f"than truncate it, got {bad_state!r} (reason "
        f"{bad_status.get('StateChangeReason')!r}, rows would have been {spills_rows!r})")

    reason = bad_status["StateChangeReason"]
    # The reader names whichever stored file it failed on, so the reason is matched exactly
    # against each object this check wrote under the table location.
    named = [k for k in keys_before
             if reason == f"HIVE_CURSOR_ERROR: Failed to read Parquet file: s3://{data_bucket}/{k}"]
    assert len(named) == 1, (
        f"the failure must name the reader that gave up and the object it could not read, one of "
        f"this check's own {keys_before!r} in s3://{data_bucket}/, got {reason!r}")

    athena_error = bad_status["AthenaError"]
    assert athena_error["ErrorCategory"] == 2, (
        f"a declaration that cannot hold the customer's own data is a USER-category error (2), got "
        f"ErrorCategory={athena_error['ErrorCategory']!r}")
    assert athena_error["ErrorType"] == 1001, (
        f"real AWS classifies an unreadable Parquet value as ErrorType 1001, got "
        f"{athena_error['ErrorType']!r}")
    assert athena_error["Retryable"] is False, (
        f"the value will not fit on a retry either, so Retryable must be False, got "
        f"{athena_error['Retryable']!r}")

    # --- the effect is ABSENT: no rows at all, not even the two that WOULD have fitted ---
    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    assert code == "InvalidRequestException", (
        f"a FAILED query must expose no result set, so GetQueryResults must reject the read; it "
        f"returned {code!r}")
    assert message == "Query did not finish successfully. Final query state: FAILED", (
        f"unexpected GetQueryResults refusal message: {message!r}")
    keys_after = _keys_under(s3, data_bucket, "spills/")
    assert keys_after == keys_before, (
        f"a failed read must not touch the data it could not parse: s3://{data_bucket}/spills/ "
        f"held {keys_before!r} and now holds {keys_after!r}")

    # --- positive control, same file: the SAME narrowing over in-range values succeeds ---
    good_qid = _run_sql(athena, out,
                        f"SELECT id, name FROM {_dml_name(database, fits)} ORDER BY id",
                        database=database)
    good_cols, good_rows = _result(athena, good_qid)
    assert good_cols == [("id", "tinyint"), ("name", "varchar")], (
        f"the surviving table must report the narrowed type it was given, got {good_cols!r}")
    assert good_rows == fits_rows, (
        f"narrowing is legal when every stored value fits, so the identical tinyint declaration "
        f"must return {fits_rows!r} exactly; got {good_rows!r}. The rejection above is therefore "
        f"driven by the stored magnitude, not by the narrowing itself")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
