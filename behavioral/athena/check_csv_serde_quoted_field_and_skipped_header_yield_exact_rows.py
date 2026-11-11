"""csv-serde-quoted-field-and-skipped-header-yield-exact-rows."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "csv-serde-quoted-field-and-skipped-header-yield-exact-rows"
GROUP = "query-execution"
SERVICES = ["athena"]

#: (id, label) pairs whose LABELS are the point: one embeds the separator inside quotes, one
#: embeds a doubled quote character, one is unquoted. A target that splits each line on commas
#: returns four columns for row 1 and cannot produce these values at all.
_ROWS = (
    (1, 'hello, world'),
    (2, 'say "hi"'),
    (3, 'plain'),
)
_HEADER = "id,label,amount"


def _dataset():
    """The CSV bytes (header + RFC4180-quoted rows) and the decoded rows, one source of truth."""
    lines = [_HEADER]
    for idx, (row_id, label) in enumerate(_ROWS):
        needs_quotes = "," in label or '"' in label
        rendered = '"' + label.replace('"', '""') + '"' if needs_quotes else label
        lines.append(f"{row_id},{rendered},{(idx + 1) * 5}")
    body = ("\n".join(lines) + "\n").encode()
    expected = [[str(row_id), label, str((idx + 1) * 5)]
                for idx, (row_id, label) in enumerate(_ROWS)]
    return body, expected


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket: Athena also writes `<qid>.csv`, `<qid>.csv.metadata`
    and `<qid>.txt` into the output location, so DeleteBucket alone would fail and leak cost."""
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
    timeout so a truncated poll is never graded as a result."""
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


def _result_set(athena, qid):
    return athena.get_query_results(QueryExecutionId=qid)["ResultSet"]


def _data_rows(result_set):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:]."""
    return [[d.get("VarCharValue") for d in r["Data"]] for r in result_set["Rows"][1:]]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers)."""
    return f'"{database}"."{table}"'


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """OpenCSVSerde honours RFC4180 quoting and skip.header.line.count: a quoted comma stays in one
    field, a doubled quote becomes one quote, the header is not a row, and declared int/bigint hold.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/csv-serde.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, expected = _dataset()
    # A FIXTURE guard, not an assertion about the target: the uploaded bytes must really contain a
    # quoted separator and a doubled quote, or the legs below would prove nothing.
    text = body.decode()
    assert '"hello, world"' in text and '""hi""' in text, (
        f"_ROWS no longer produces a quoted separator and a doubled quote: {text!r}")
    s3.put_object(Bucket=data_bucket, Key="csv/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-csv-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the table too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` "
        "(`id` int, `label` string, `amount` bigint) "
        "ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde' "
        "WITH SERDEPROPERTIES ("
        "'separatorChar' = ',', 'quoteChar' = '\"', 'escapeChar' = '\\\\') "
        f"LOCATION 's3://{data_bucket}/csv/' "
        "TBLPROPERTIES ('skip.header.line.count' = '1')")

    table_name = _dml_name(database, table)

    # --- leg 1: every field parsed exactly, header excluded, order server-side ---
    sel_qid = _run_sql(
        athena, out,
        f"SELECT id, label, amount FROM {table_name} ORDER BY id", database=database)
    sel = _result_set(athena, sel_qid)
    rows = _data_rows(sel)
    assert rows == expected, (
        f"the CSV reader must honour the quote character and skip the header line: expected "
        f"{expected!r}, got {rows!r}")

    scanned = _scanned(athena, sel_qid)
    assert scanned == len(body), (
        f"the rows must have been parsed out of the {len(body)} bytes this check uploaded — the "
        f"header line included, since skipping is a reader concern and not a smaller read — got "
        f"DataScannedInBytes={scanned!r}")

    types = [(c["Name"], c["Type"]) for c in sel["ResultSetMetadata"]["ColumnInfo"]]
    assert types == [("id", "integer"), ("label", "varchar"), ("amount", "bigint")], (
        f"the DDL's declared column types must be honoured even though OpenCSVSerde reads every "
        f"raw field as text, got {types!r}")

    # --- leg 2: the skipped header is not a row. A reader that forgot the property counts 4.
    count_qid = _run_sql(athena, out, f"SELECT count(*) FROM {table_name}", database=database)
    count_rows = _data_rows(_result_set(athena, count_qid))
    assert count_rows == [[str(len(_ROWS))]], (
        f"skip.header.line.count = 1 must exclude the header from the row count, so count(*) is "
        f"{len(_ROWS)} and not {len(_ROWS) + 1}, got {count_rows!r}")

    # --- leg 3: the embedded separator really stayed inside one field, so the value can be
    #     matched server-side in full. A split-on-comma reader has no column holding it.
    embedded = next(label for _, label in _ROWS if "," in label)
    eq_qid = _run_sql(
        athena, out,
        f"SELECT id FROM {table_name} WHERE label = '{embedded}' ORDER BY id", database=database)
    eq_rows = _data_rows(_result_set(athena, eq_qid))
    expected_ids = [[str(row_id)] for row_id, label in _ROWS if label == embedded]
    assert eq_rows == expected_ids, (
        f"the quoted field {embedded!r} must be one comparable value, so an equality predicate on "
        f"it must select exactly {expected_ids!r}, got {eq_rows!r}")

    # --- leg 4: the declared bigint column really is numeric, not the SerDe's raw text. Ordering
    #     and arithmetic over it must agree with the Python-computed values.
    sum_qid = _run_sql(
        athena, out, f"SELECT sum(amount) FROM {table_name}", database=database)
    sum_rows = _data_rows(_result_set(athena, sum_qid))
    expected_sum = sum(int(row[2]) for row in expected)
    assert sum_rows == [[str(expected_sum)]], (
        f"sum(amount) must equal the {expected_sum} computed from the uploaded rows, which is only "
        f"possible if the text fields were cast to the declared bigint, got {sum_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
