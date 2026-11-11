"""schemaevo-dropped-column-is-recovered-by-re-adding-it."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schemaevo-dropped-column-is-recovered-by-re-adding-it"
GROUP = "schema-evolution"
SERVICES = ["athena"]



def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own artifacts (`<qid>.csv`, `<qid>.csv.metadata`, `<qid>.txt` for DDL and
    `<qid>-manifest.csv` for an UNLOAD) into the output location, so a bucket that only ever
    received our uploads is still non-empty at teardown, and DeleteBucket on a non-empty bucket
    fails. A failed DeleteBucket is the one real cost leak in this service.
    """
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
    """(query id, terminal state, Status envelope) for a statement that is EXPECTED to fail.

    Deliberately separate from `_run_sql`: the rejection here is asynchronous, so the caller needs
    the envelope rather than an exception, and it must be able to assert on a SUCCEEDED state as
    the over-permissiveness it would be.
    """
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
    return qid, state, status


def _result(athena, qid):
    """((name, type) per column, data rows) for a SELECT, fully PAGINATED.

    Only the FIRST page repeats the column names as row 0, so the header is dropped from that page
    alone. Rows are a LIST, never a set: ORDER BY makes the order a server-side guarantee and an
    emulator that shuffles must fail.
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


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


def _stage_parquet(athena, s3, out, database, bucket, select_sql, generation, lake_prefix):
    """Write ONE generation of real Parquet under a table's LOCATION and return its keys.

    UNLOAD is the engine's own Parquet writer, so the physical column types under test are the ones
    the service itself chose for the SELECT's output types. UNLOAD refuses a non-empty destination,
    so each generation lands in its own staging prefix and is copied into the flat prefix the
    external table points at. The PAR1 assertion is what makes this a byte-level claim rather than
    a claim about a SUCCEEDED status.
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
    """Dropping a Parquet column with REPLACE COLUMNS is a catalogue edit only: SELECT * shows the
    remaining column, the table's objects are byte-identical, the dropped column is rejected with
    COLUMN_NOT_FOUND, and ADD COLUMNS re-declaring it returns the original values, not NULLs."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker, so the recovered values cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(
        Bucket=data_bucket, Key="src/rows.csv",
        Body=f"1,alpha-{marker}\n2,bravo-{marker}\n3,charlie-{marker}\n".encode())

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

    expected = [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"], ["3", f"charlie-{marker}"]]
    lake_name = _dml_name(database, lake)
    star_sql = f"SELECT * FROM {lake_name} ORDER BY id"

    base_qid = _run_sql(athena, out, star_sql, database=database)
    base_cols, base_rows = _result(athena, base_qid)
    assert base_cols == [("id", "integer"), ("name", "varchar")], (
        f"SELECT * must expand to the two declared columns before the drop, got {base_cols!r}")
    assert base_rows == expected, (
        f"the pre-drop read must return this run's exact rows in ORDER BY id order; the marker was "
        f"{marker!r} and the read gave {base_rows!r}")

    # --- act: drop the second column from the CATALOGUE ---
    keys_before = _keys_under(s3, data_bucket, lake_prefix)
    _run_sql(athena, out, f"ALTER TABLE `{database}`.`{lake}` REPLACE COLUMNS (`id` int)")
    keys_after = _keys_under(s3, data_bucket, lake_prefix)
    assert keys_after == keys_before, (
        f"dropping a column must not rewrite, add or remove a single object under "
        f"s3://{data_bucket}/{lake_prefix}: it held {keys_before!r} and now holds {keys_after!r}")

    dropped_qid = _run_sql(athena, out, star_sql, database=database)
    dropped_cols, dropped_rows = _result(athena, dropped_qid)
    assert dropped_cols == [("id", "integer")], (
        f"SELECT * must expand to the one surviving column, got {dropped_cols!r}")
    assert dropped_rows == [[row[0]] for row in expected], (
        f"the surviving column must keep its own values, unshifted by the drop; expected "
        f"{[[row[0]] for row in expected]!r}, got {dropped_rows!r}")

    # --- the dropped column is genuinely gone from the catalogue: naming it is an error ---
    _, missing_state, missing_status = _terminal_status(
        athena, out, f"SELECT name FROM {lake_name}", database=database)
    assert missing_state == "FAILED", (
        f"a column the catalogue no longer declares must not be selectable even though the files "
        f"still hold it, got {missing_state!r} (reason "
        f"{missing_status.get('StateChangeReason')!r})")
    missing_reason = missing_status["StateChangeReason"]
    assert missing_reason.startswith("COLUMN_NOT_FOUND:"), (
        f"the failure must be the planner's own unknown-column error rather than a reader error, "
        f"got {missing_reason!r}")

    # --- re-declare it: the values come back from the files, they were never NULL ---
    _run_sql(athena, out, f"ALTER TABLE `{database}`.`{lake}` ADD COLUMNS (`name` string)")
    restored_qid = _run_sql(athena, out, star_sql, database=database)
    restored_cols, restored_rows = _result(athena, restored_qid)
    assert restored_cols == base_cols, (
        f"re-adding the column must restore the original resolved schema: it was {base_cols!r} and "
        f"came back {restored_cols!r}")
    assert restored_rows == expected, (
        f"the files never stopped holding the column, so re-declaring it must recover this run's "
        f"exact values rather than NULL-fill them: expected {expected!r}, got {restored_rows!r}")
    restored_scanned = _scanned(athena, restored_qid)
    assert restored_scanned > 0, (
        f"the recovery must come from scanning the Parquet files, got "
        f"DataScannedInBytes={restored_scanned!r} — a result set answered from remembered rows "
        f"scans nothing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
