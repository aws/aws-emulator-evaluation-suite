"""schemaevo-add-column-reads-null-from-older-parquet-files."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schemaevo-add-column-reads-null-from-older-parquet-files"
GROUP = "schema-evolution"
SERVICES = ["athena"]


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, including Athena's own query artifacts, then DeleteBucket."""
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

    Only the first page repeats the header row. A NULL arrives as an absent `VarCharValue`.
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
    """Athena parses DML with the Trino parser, which needs double-quoted identifiers; a backtick
    in a SELECT is refused synchronously."""
    return f'"{database}"."{table}"'


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix only this check writes, sorted and paginated."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


def _stage_parquet(athena, s3, out, database, bucket, select_sql, generation, lake_prefix):
    """UNLOAD one generation of Parquet, copy it under the table's LOCATION, and return its keys.

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
    """ALTER TABLE ADD COLUMNS changes only the catalogue: older Parquet files read NULL in the new
    column with values unshifted, and a newer file carrying it reads its value, resolved by name.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/types-of-updates.html
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
    v1_keys = _stage_parquet(
        athena, s3, out, database, data_bucket,
        f"SELECT id, name FROM {_dml_name(database, src)} ORDER BY id", "v1", lake_prefix)
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{lake}` (`id` int, `name` string) "
        f"STORED AS PARQUET LOCATION 's3://{data_bucket}/{lake_prefix}'")

    base_qid = _run_sql(athena, out,
                        f"SELECT id, name FROM {_dml_name(database, lake)} ORDER BY id",
                        database=database)
    base_cols, base_rows = _result(athena, base_qid)
    assert base_cols == [("id", "integer"), ("name", "varchar")], (
        f"the pre-evolution table must report its two declared columns, got {base_cols!r}")
    assert base_rows == [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"],
                        ["3", f"charlie-{marker}"]], (
        f"the pre-evolution read must return this run's exact rows in ORDER BY id order; the "
        f"marker was {marker!r} and the read gave {base_rows!r}")

    before = _keys_under(s3, data_bucket, lake_prefix)
    assert before == sorted(v1_keys), (
        f"before the ALTER the table location must hold exactly the generation-1 files "
        f"{sorted(v1_keys)!r}, got {before!r}")
    _run_sql(athena, out, f"ALTER TABLE `{database}`.`{lake}` ADD COLUMNS (`grade` string)")
    after = _keys_under(s3, data_bucket, lake_prefix)
    assert after == before, (
        f"ADD COLUMNS is a catalogue-only change and must not rewrite, add or remove a single "
        f"object under s3://{data_bucket}/{lake_prefix}: it held {before!r} and now holds "
        f"{after!r}")

    evolved_qid = _run_sql(
        athena, out, f"SELECT id, name, grade FROM {_dml_name(database, lake)} ORDER BY id",
        database=database)
    evolved_cols, evolved_rows = _result(athena, evolved_qid)
    assert evolved_cols == [("id", "integer"), ("name", "varchar"), ("grade", "varchar")], (
        f"the added column must appear LAST in the resolved schema with its declared type, got "
        f"{evolved_cols!r}")
    assert evolved_rows == [["1", f"alpha-{marker}", None], ["2", f"bravo-{marker}", None],
                           ["3", f"charlie-{marker}", None]], (
        f"every pre-existing row must survive the ALTER with its own values unshifted and NULL "
        f"(an ABSENT VarCharValue, not '') in the added column, got {evolved_rows!r}")
    evolved_scanned = _scanned(athena, evolved_qid)
    assert evolved_scanned > 0, (
        f"the post-ALTER read must scan the real Parquet files, got "
        f"DataScannedInBytes={evolved_scanned!r} — a result set answered from the catalogue alone "
        f"scans nothing")

    count_qid = _run_sql(
        athena, out,
        f"SELECT count(*) AS total, count(grade) AS graded FROM {_dml_name(database, lake)}",
        database=database)
    _, count_rows = _result(athena, count_qid)
    assert count_rows == [["3", "0"]], (
        f"ADD COLUMNS must not lose or duplicate a row, and count() must skip the NULLs it "
        f"introduced: expected total=3 graded=0, got {count_rows!r}")

    _stage_parquet(
        athena, s3, out, database, data_bucket,
        f"SELECT CAST(4 AS integer) id, 'delta-{marker}' name, 'A' grade", "v2", lake_prefix)
    mixed_qid = _run_sql(
        athena, out, f"SELECT id, name, grade FROM {_dml_name(database, lake)} ORDER BY id",
        database=database)
    mixed_cols, mixed_rows = _result(athena, mixed_qid)
    assert mixed_cols == evolved_cols, (
        f"landing a wider file must not change the resolved schema, which the catalogue owns: it "
        f"was {evolved_cols!r} and is now {mixed_cols!r}")
    assert mixed_rows == [["1", f"alpha-{marker}", None], ["2", f"bravo-{marker}", None],
                          ["3", f"charlie-{marker}", None], ["4", f"delta-{marker}", "A"]], (
        f"two Parquet generations of different widths must coexist under one table, each row "
        f"resolving its own columns by NAME — the two-column files still NULL, the three-column "
        f"file carrying 'A' — got {mixed_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
