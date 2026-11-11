"""schemaevo-index-access-reorder-fails-while-name-based-reorder-resolves."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schemaevo-index-access-reorder-fails-while-name-based-reorder-resolves"
GROUP = "schema-evolution"
SERVICES = ["athena"]

# Switches Athena's Parquet reader from resolving columns by name (default) to ordinal position.
_INDEX_ACCESS = "parquet.column.index.access"


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, including Athena's own result artifacts, then the bucket."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    # CreateBucket rejects an explicit LocationConstraint for us-east-1.
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
    """(query id, terminal state, Status envelope) for a statement expected to fail."""
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
    return qid, state, status


def _result(athena, qid):
    """((name, type) per column, data rows in order) for a SELECT, fully paginated.

    Only the first page repeats the column names as row 0, so the header is dropped there alone.
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
    """A double-quoted DML identifier; Athena's DDL uses backticks but DML (Trino) refuses them."""
    return f'"{database}"."{table}"'


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix in a bucket this check created, sorted and paginated."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


def _error(fn):
    """The AWS error (code, message) raised by `fn`; an unexpected success fails."""
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
    """Write one generation of real Parquet (via UNLOAD) under a table's LOCATION; return its keys.

    UNLOAD refuses a non-empty destination, so it writes to a staging prefix that is then copied.
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
    """A reordered Parquet declaration reads correctly under default name resolution, but with
    parquet.column.index.access fails with an exact HIVE_BAD_DATA and no result set, and reads
    correctly again once the declaration is back in physical order.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # The two columns have different physical types (INT32, BINARY), so a positional mismatch fails.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(
        Bucket=data_bucket, Key="src/rows.csv",
        Body=f"1,alpha-{marker}\n2,bravo-{marker}\n".encode())

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    lake = ctx.unique_name("sim2real-behav-lake-").replace("-", "_")
    # DROP DATABASE is itself an Athena query; LIFO keeps the results bucket alive until it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    lake_prefix = "lake/"
    # The files' PHYSICAL column order is (id INT32, name BINARY) — fixed here, never changed again.
    _stage_parquet(
        athena, s3, out, database, data_bucket,
        f"SELECT id, name FROM {_dml_name(database, src)} ORDER BY id", "v1", lake_prefix)
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{lake}` (`id` int, `name` string) "
        f"STORED AS PARQUET LOCATION 's3://{data_bucket}/{lake_prefix}'")

    expected = [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"]]
    shifted = [[f"alpha-{marker}", "1"], [f"bravo-{marker}", "2"]]
    lake_name = _dml_name(database, lake)
    select_sql = f"SELECT id, name FROM {lake_name} ORDER BY id"

    # Reorder the declaration under default name-based resolution.
    _run_sql(athena, out,
             f"ALTER TABLE `{database}`.`{lake}` REPLACE COLUMNS (`name` string, `id` int)")
    keys_before = _keys_under(s3, data_bucket, lake_prefix)
    name_qid = _run_sql(athena, out, select_sql, database=database)
    name_cols, name_rows = _result(athena, name_qid)
    assert name_cols == [("id", "integer"), ("name", "varchar")], (
        f"the projection's own order governs the result set, not the table's, got {name_cols!r}")
    assert name_rows == expected, (
        f"under default NAME-based resolution a reordered declaration must still return each value "
        f"under its own column: expected {expected!r}, and the shifted answer a position-based "
        f"reader would give is {shifted!r}; got {name_rows!r}")

    # Same table and declaration; only the resolution mode changes.
    _run_sql(athena, out, f"ALTER TABLE `{database}`.`{lake}` "
                          f"SET TBLPROPERTIES ('{_INDEX_ACCESS}'='true')")
    bad_qid, bad_state, bad_status = _terminal_status(athena, out, select_sql, database=database)
    assert bad_state == "FAILED", (
        f"under position-based resolution a declaration whose order contradicts the files must "
        f"reach FAILED rather than return the other column's data, got {bad_state!r} (reason "
        f"{bad_status.get('StateChangeReason')!r})")

    reason = bad_status["StateChangeReason"]
    # Which file the reader names is not deterministic, so match against each object written.
    named = [k for k in keys_before
             if reason == (f"HIVE_BAD_DATA: Malformed Parquet file. Field id's type INT32 in "
                           f"parquet file s3://{data_bucket}/{k} is incompatible with type "
                           f"varchar defined in table schema [s3://{data_bucket}/{k}]")]
    assert len(named) == 1, (
        f"the failure must be the Parquet reader's own incompatible-type error, naming the field "
        f"at the contradicted position, its PHYSICAL type, the declared varchar and one of this "
        f"check's own objects {keys_before!r}, got {reason!r}")

    athena_error = bad_status["AthenaError"]
    assert athena_error["ErrorCategory"] == 2, (
        f"a declaration that contradicts the customer's own files is a USER-category error (2), "
        f"got ErrorCategory={athena_error['ErrorCategory']!r}")
    assert athena_error["ErrorType"] == 1002, (
        f"real AWS classifies malformed-input Parquet as ErrorType 1002, got "
        f"{athena_error['ErrorType']!r}")
    assert athena_error["Retryable"] is False, (
        f"the positions will not line up on a retry, so Retryable must be False, got "
        f"{athena_error['Retryable']!r}")

    # A FAILED query exposes no result set.
    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    assert code == "InvalidRequestException", (
        f"a FAILED query must expose no result set, so GetQueryResults must reject the read rather "
        f"than return {shifted!r}; it returned {code!r}")
    assert message == "Query did not finish successfully. Final query state: FAILED", (
        f"unexpected GetQueryResults refusal message: {message!r}")
    keys_after = _keys_under(s3, data_bucket, lake_prefix)
    assert keys_after == keys_before, (
        f"a failed read must not touch the data it could not parse: "
        f"s3://{data_bucket}/{lake_prefix} held {keys_before!r} and now holds {keys_after!r}")

    # Same property, declaration back in the files' physical order.
    _run_sql(athena, out,
             f"ALTER TABLE `{database}`.`{lake}` REPLACE COLUMNS (`id` int, `name` string)")
    good_qid = _run_sql(athena, out, select_sql, database=database)
    good_cols, good_rows = _result(athena, good_qid)
    assert good_cols == name_cols, (
        f"position-based resolution over a correctly ordered declaration must resolve the same "
        f"schema: it was {name_cols!r} and came back {good_cols!r}")
    assert good_rows == expected, (
        f"position-based resolution is not itself broken — with the declaration back in the files' "
        f"physical order the same query must return {expected!r} — got {good_rows!r}. The failure "
        f"above is therefore attributable to the ORDER, not to the property")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
