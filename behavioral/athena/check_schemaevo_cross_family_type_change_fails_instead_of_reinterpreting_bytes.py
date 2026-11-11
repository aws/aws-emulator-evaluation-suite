"""schemaevo-cross-family-type-change-fails-instead-of-reinterpreting-bytes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schemaevo-cross-family-type-change-fails-instead-of-reinterpreting-bytes"
GROUP = "schema-evolution"
SERVICES = ["athena"]


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


def _terminal_status(athena, out, sql, database=None):
    """(query id, terminal state, Status envelope) for a statement EXPECTED to fail."""
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
    return qid, state, status


def _result(athena, qid):
    """((name, type) per column, data rows) for a SELECT, fully paginated.

    Only the first page carries the header row; rows stay ordered because ORDER BY guarantees it.
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


def _dml_name(database, table):
    """Double-quoted name for DML: Athena parses DML with Trino, which rejects backticks."""
    return f'"{database}"."{table}"'


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix this check created, paginated and sorted."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


def _error(fn):
    """The AWS error (code, message) raised by `fn`; an unexpected success fails the check."""
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
    """Write one generation of real Parquet (via UNLOAD) under a table's LOCATION; return keys."""
    # UNLOAD refuses a non-empty destination, so stage per generation and copy into the lake.
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
    """Declaring a stored Parquet string column `int` is accepted, then every read FAILS with
    HIVE_BAD_DATA instead of reinterpreting bytes; no result set, data untouched, restore recovers.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/types-of-updates.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker, so the rows that come back cannot be a hardcoded fixture. The values in
    # the string column are deliberately NOT digit strings: a reader that "helpfully" parses text
    # into integers has nothing to parse, so the only ways out are the right error or garbage.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(
        Bucket=data_bucket, Key="src/rows.csv",
        Body=f"1,alpha-{marker}\n2,bravo-{marker}\n".encode())

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

    lake_prefix = "lake/"
    _stage_parquet(
        athena, s3, out, database, data_bucket,
        f"SELECT id, name FROM {_dml_name(database, src)} ORDER BY id", "v1", lake_prefix)
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{lake}` (`id` int, `name` string) "
        f"STORED AS PARQUET LOCATION 's3://{data_bucket}/{lake_prefix}'")

    expected = [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"]]
    lake_name = _dml_name(database, lake)

    # --- positive context: the table reads its own rows at the declared types ---
    base_qid = _run_sql(athena, out, f"SELECT id, name FROM {lake_name} ORDER BY id",
                        database=database)
    base_cols, base_rows = _result(athena, base_qid)
    assert base_cols == [("id", "integer"), ("name", "varchar")], (
        f"the table must report its two declared columns before the change, got {base_cols!r}")
    assert base_rows == expected, (
        f"the pre-change read must return this run's exact rows in ORDER BY id order; the marker "
        f"was {marker!r} and the read gave {base_rows!r}")

    # --- break exactly ONE thing: declare the stored STRING column as an integer ---
    keys_before = _keys_under(s3, data_bucket, lake_prefix)
    # This DDL SUCCEEDS on real AWS: the catalogue does not validate a declaration against the
    # files, so _run_sql's own SUCCEEDED requirement is the assertion.
    _run_sql(athena, out,
             f"ALTER TABLE `{database}`.`{lake}` REPLACE COLUMNS (`id` int, `name` int)")

    bad_qid, bad_state, bad_status = _terminal_status(
        athena, out, f"SELECT id, name FROM {lake_name} ORDER BY id", database=database)
    assert bad_state == "FAILED", (
        f"reading a UTF-8 Parquet column through an `int` declaration must reach FAILED rather "
        f"than reinterpret the bytes, got {bad_state!r} (reason "
        f"{bad_status.get('StateChangeReason')!r})")

    reason = bad_status["StateChangeReason"]
    # Which file the reader names is not deterministic (first split it failed on), so match
    # the exact reason against each object under the table location.
    named = [k for k in keys_before
             if reason == (f"HIVE_BAD_DATA: Malformed Parquet file. Field name's type BINARY in "
                           f"parquet file s3://{data_bucket}/{k} is incompatible with type "
                           f"integer defined in table schema [s3://{data_bucket}/{k}]")]
    assert len(named) == 1, (
        f"the failure must be the Parquet reader's own incompatible-type error, naming the "
        f"offending column, its PHYSICAL type, the declared type and one of this check's own "
        f"objects {keys_before!r}, got {reason!r}")

    athena_error = bad_status["AthenaError"]
    assert athena_error["ErrorCategory"] == 2, (
        f"a declaration that contradicts the customer's own files is a USER-category error (2), "
        f"got ErrorCategory={athena_error['ErrorCategory']!r}")
    assert athena_error["ErrorType"] == 1002, (
        f"real AWS classifies malformed-input Parquet as ErrorType 1002, got "
        f"{athena_error['ErrorType']!r}")
    assert athena_error["Retryable"] is False, (
        f"the bytes will not become integers on a retry, so Retryable must be False, got "
        f"{athena_error['Retryable']!r}")

    # --- the effect is ABSENT: no result set, and not one byte of the data touched ---
    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    assert code == "InvalidRequestException", (
        f"a FAILED query must expose no result set, so GetQueryResults must reject the read; it "
        f"returned {code!r}")
    assert message == "Query did not finish successfully. Final query state: FAILED", (
        f"unexpected GetQueryResults refusal message: {message!r}")
    keys_after = _keys_under(s3, data_bucket, lake_prefix)
    assert keys_after == keys_before, (
        f"a failed read must not touch the data it could not parse: "
        f"s3://{data_bucket}/{lake_prefix} held {keys_before!r} and now holds {keys_after!r}")

    # --- positive control, same file: restoring the declaration restores the rows ---
    _run_sql(athena, out,
             f"ALTER TABLE `{database}`.`{lake}` REPLACE COLUMNS (`id` int, `name` string)")
    good_qid = _run_sql(athena, out, f"SELECT id, name FROM {lake_name} ORDER BY id",
                        database=database)
    good_cols, good_rows = _result(athena, good_qid)
    assert good_cols == base_cols, (
        f"restoring the declaration must restore the resolved schema: it was {base_cols!r} and "
        f"came back {good_cols!r}")
    assert good_rows == expected, (
        f"the rejected read damaged nothing, so the restored declaration must return {expected!r} "
        f"exactly; got {good_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
