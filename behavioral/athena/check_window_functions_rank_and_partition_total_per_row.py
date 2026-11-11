"""window-functions-rank-and-partition-total-per-row."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "window-functions-rank-and-partition-total-per-row"
GROUP = "query-execution"
SERVICES = ["athena"]

#: Two partitions of DIFFERENT sizes, amounts distinct within each partition (so `row_number()` is
#: deterministic), one negative value (so a partition total cannot be confused with a count or a
#: max) and the row order on S3 deliberately NOT the ranked order.
_ROWS = (
    ("alpha", 5),
    ("beta", 40),
    ("alpha", 7),
    ("beta", -3),
    ("beta", 2),
)



def _dataset():
    """The CSV bytes and the expected windowed rows, from one source of truth.

    The expected rows are COMPUTED here — descending sort per category, 1-based rank, partition sum — so a
    target cannot satisfy it by echoing anything it was told.
    """
    body = "".join(f"{i},{cat},{amt}\n" for i, (cat, amt) in enumerate(_ROWS)).encode()
    expected = []
    for cat in sorted({cat for cat, _ in _ROWS}):
        amounts = sorted((amt for c, amt in _ROWS if c == cat), reverse=True)
        total = sum(amounts)
        for rank, amt in enumerate(amounts, start=1):
            expected.append([cat, str(amt), str(rank), str(total)])
    return body, expected


def _totals():
    totals = {}
    for cat, amt in _ROWS:
        totals[cat] = totals.get(cat, 0) + amt
    return totals


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location, so DeleteBucket alone would fail and a failed
    DeleteBucket is this service's most likely cost leak."""
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


def _result_set(athena, qid):
    return athena.get_query_results(QueryExecutionId=qid)["ResultSet"]


def _data_rows(result_set):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:].
    Returned as a LIST: the queries below all carry ORDER BY, making the order a guarantee."""
    return [[d.get("VarCharValue") for d in r["Data"]] for r in result_set["Rows"][1:]]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers)."""
    return f'"{database}"."{table}"'


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`row_number() OVER (PARTITION BY cat ORDER BY amount DESC)` ranks each category's rows and
    `sum(amount) OVER (PARTITION BY cat)` repeats the category total on every row, without
    collapsing rows, exactly matching values computed in Python from the uploaded tuples."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, expected = _dataset()
    totals = _totals()
    # FIXTURE guards, not assertions about the target: row_number() is only deterministic if the
    # amounts are distinct within each category, and the totals must differ between categories or a
    # per-row total could be right for the wrong partition.
    for cat in totals:
        amounts = [amt for c, amt in _ROWS if c == cat]
        assert len(set(amounts)) == len(amounts), (
            f"_ROWS must give category {cat!r} distinct amounts so the ranking is deterministic, "
            f"got {amounts!r}")
    assert len(set(totals.values())) == len(totals), (
        f"_ROWS must give the categories distinct totals so a per-row total identifies its "
        f"partition, got {totals!r}")
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-win-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the table too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` "
        "(`id` int, `cat` string, `amount` bigint) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    table_name = _dml_name(database, table)

    # --- leg 1: rank and partition total, per row, in a server-side order ---
    win_qid = _run_sql(
        athena, out,
        "SELECT cat, amount, "
        "row_number() OVER (PARTITION BY cat ORDER BY amount DESC) AS rn, "
        "sum(amount) OVER (PARTITION BY cat) AS cat_total "
        f"FROM {table_name} ORDER BY cat, rn",
        database=database)
    win = _result_set(athena, win_qid)
    rows = _data_rows(win)
    assert rows == expected, (
        f"the window functions must rank within each category and repeat that category's total on "
        f"every row: expected {expected!r}, got {rows!r}")

    scanned = _scanned(athena, win_qid)
    assert scanned == len(body), (
        f"the result must have been computed over the {len(body)} bytes this check uploaded, got "
        f"DataScannedInBytes={scanned!r}")

    types = [(c["Name"], c["Type"]) for c in win["ResultSetMetadata"]["ColumnInfo"]]
    assert types == [("cat", "varchar"), ("amount", "bigint"), ("rn", "bigint"),
                     ("cat_total", "bigint")], (
        f"the window columns must carry the engine's own types — row_number() is bigint, not "
        f"integer — got {types!r}")

    # --- leg 2: the window did NOT collapse the rows. An engine that implemented OVER as a GROUP
    #     BY returns one row per category and still looks plausible on leg 1's first rows.
    assert len(rows) == len(_ROWS), (
        f"a window function preserves the row count, so the result must have {len(_ROWS)} rows and "
        f"not one per category, got {len(rows)}")

    # --- leg 3: the repeated total really is the aggregate, cross-checked against the collapsing
    #     form of the same computation in the same file.
    grp_qid = _run_sql(
        athena, out,
        f"SELECT cat, sum(amount) FROM {table_name} GROUP BY cat ORDER BY cat", database=database)
    grp_rows = _data_rows(_result_set(athena, grp_qid))
    expected_grp = [[cat, str(totals[cat])] for cat in sorted(totals)]
    assert grp_rows == expected_grp, (
        f"the grouped form must agree with the per-row totals asserted above: expected "
        f"{expected_grp!r}, got {grp_rows!r}")

    # --- leg 4: the rank orders by amount, not by the row order on S3. Selecting the top-ranked
    #     row of each category must return the MAXIMUM amount, which is not the first row written.
    top_qid = _run_sql(
        athena, out,
        "SELECT cat, amount FROM ("
        "SELECT cat, amount, row_number() OVER (PARTITION BY cat ORDER BY amount DESC) AS rn "
        f"FROM {table_name}) WHERE rn = 1 ORDER BY cat",
        database=database)
    top_rows = _data_rows(_result_set(athena, top_qid))
    expected_top = [[cat, str(max(amt for c, amt in _ROWS if c == cat))]
                    for cat in sorted(totals)]
    assert top_rows == expected_top, (
        f"rn = 1 must select each category's largest amount, which is not the first row of that "
        f"category in the uploaded object: expected {expected_top!r}, got {top_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
