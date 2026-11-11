"""group-by-aggregation-matches-independently-computed-values."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "group-by-aggregation-matches-independently-computed-values"
GROUP = "query-execution"
SERVICES = ["athena"]

#: Deliberately uneven group sizes and a negative value, so a target that returns a constant, a
#: single row, or the ungrouped total cannot coincide with the right answer.
_ROWS = (
    ("alpha", 5),
    ("alpha", 7),
    ("alpha", -2),
    ("beta", 40),
    ("beta", 2),
    ("gamma", 100),
    ("gamma", 100),
    ("gamma", 1),
    ("gamma", -50),
)


def _dataset():
    """The CSV bytes and the independently computed per-group oracle, from one source of truth."""
    body = "".join(f"{i},{cat},{amt}\n" for i, (cat, amt) in enumerate(_ROWS)).encode()
    groups = {}
    for cat, amt in _ROWS:
        groups.setdefault(cat, []).append(amt)
    expected = [
        [cat, str(len(vals)), str(sum(vals)), str(min(vals)), str(max(vals))]
        for cat, vals in sorted(groups.items())
    ]
    return body, expected, groups


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location, and this check additionally writes CTAS/INSERT data
    files, so DeleteBucket alone would fail. No bare `except Exception`: a teardown that cannot
    finish must surface rather than leak silently."""
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


def _start_query(athena, out, query_string, workgroup=None, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline; RAISES on
    timeout so a truncated poll can never record a wrong oracle. The terminal set excludes nothing
    terminal, and callers assert WHICH state was reached."""
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


def _run_sql(athena, out, sql, database=None):
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _data_rows(results):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:].
    Returned as a LIST: ORDER BY makes the order a server-side guarantee and a target that
    shuffles must fail. Hard-subscripted so a missing ResultSet raises."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML goes through the Trino parser (double-quoted identifiers); DDL through Hive
    (backticks). A backtick inside a SELECT is refused synchronously by StartQueryExecution."""
    return f'"{database}"."{table}"'


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GROUP BY over an external table returns exactly the per-group count/sum/min/max computed
    from the uploaded tuples, HAVING filters groups server-side, and an INSERT INTO of those groups
    reports an UpdateCount equal to the rows a re-SELECT of the destination returns."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, expected_groups, groups = _dataset()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    dest = ctx.unique_name("sim2real-behav-dest-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the tables too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` "
        "(`id` int, `category` string, `amount` bigint) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    src_name = _dml_name(database, src)

    # --- leg 1: the grouped aggregate must equal the Python-computed oracle, group for group.
    agg_sql = (
        "SELECT category, count(*) AS n, sum(amount) AS total, min(amount) AS lo, "
        f"max(amount) AS hi FROM {src_name} GROUP BY category ORDER BY category")
    agg_qid = _run_sql(athena, out, agg_sql, database=database)
    agg_results = athena.get_query_results(QueryExecutionId=agg_qid)
    agg_rows = _data_rows(agg_results)
    assert agg_rows == expected_groups, (
        f"the grouped aggregate must equal the values computed from the {len(_ROWS)} uploaded "
        f"rows: expected {expected_groups!r}, got {agg_rows!r}")

    scanned = athena.get_query_execution(QueryExecutionId=agg_qid)["QueryExecution"][
        "Statistics"]["DataScannedInBytes"]
    assert scanned == len(body), (
        f"the aggregate must have been computed over the {len(body)} bytes this check uploaded, "
        f"not fabricated: DataScannedInBytes was {scanned!r}")

    types = {c["Name"]: c["Type"]
             for c in agg_results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]}
    assert types == {"category": "varchar", "n": "bigint", "total": "bigint",
                     "lo": "bigint", "hi": "bigint"}, (
        f"the aggregate columns must carry the engine's aggregate types (a client reading through "
        f"JDBC has nothing else to go on), got {types!r}")

    # --- leg 2: HAVING must filter GROUPS server-side. The threshold is derived so that it splits
    #     the real groups non-trivially — strictly between the smallest and largest group sum — so
    #     a target that ignores HAVING (returning every group) and one that returns none both fail.
    sums = {cat: sum(vals) for cat, vals in groups.items()}
    threshold = min(sums.values())
    kept = sorted(cat for cat, total in sums.items() if total > threshold)
    # A FIXTURE guard, not an assertion about the target: it checks that _ROWS still splits
    # non-trivially under this threshold, so that a later edit to _ROWS cannot quietly turn the
    # HAVING leg into something that passes for every group set.
    assert 0 < len(kept) < len(sums), (
        f"_ROWS no longer splits under the derived threshold, so the HAVING leg could not fail: "
        f"sums {sums!r}, threshold {threshold!r}, kept {kept!r}")
    having_qid = _run_sql(
        athena, out,
        f"SELECT category FROM {src_name} GROUP BY category HAVING sum(amount) > {threshold} "
        "ORDER BY category",
        database=database)
    having_rows = _data_rows(athena.get_query_results(QueryExecutionId=having_qid))
    assert having_rows == [[cat] for cat in kept], (
        f"HAVING sum(amount) > {threshold} must keep exactly {kept!r} out of "
        f"{sorted(sums)!r}, got {having_rows!r}")

    # --- leg 3: an INSERT INTO must report how many rows it wrote, and the destination must hold
    #     exactly them when read back through a different statement.
    _run_sql(
        athena, out,
        f"CREATE TABLE {_dml_name(database, dest)} WITH (format = 'TEXTFILE', "
        f"external_location = 's3://{data_bucket}/dest/') AS "
        f"SELECT category, sum(amount) AS total FROM {src_name} GROUP BY category "
        f"HAVING sum(amount) > {threshold}",
        database=database)
    dest_name = _dml_name(database, dest)
    after_ctas = _data_rows(athena.get_query_results(QueryExecutionId=_run_sql(
        athena, out, f"SELECT category, total FROM {dest_name} ORDER BY category",
        database=database)))
    assert after_ctas == [[cat, str(sums[cat])] for cat in kept], (
        f"CTAS must materialise exactly the HAVING-filtered groups with their computed sums, got "
        f"{after_ctas!r}")

    insert_qid = _run_sql(
        athena, out,
        f"INSERT INTO {dest_name} SELECT category, sum(amount) AS total FROM {src_name} "
        f"GROUP BY category ORDER BY category",
        database=database)
    insert_results = athena.get_query_results(QueryExecutionId=insert_qid)
    update_count = insert_results["UpdateCount"]
    assert update_count == len(sums), (
        f"the INSERT wrote one row per group, so UpdateCount must be exactly {len(sums)}, got "
        f"{update_count!r}")

    final_rows = _data_rows(athena.get_query_results(QueryExecutionId=_run_sql(
        athena, out, f"SELECT category, total FROM {dest_name} ORDER BY category, total",
        database=database)))
    # Sorted the way the SQL sorts it: `total` is a bigint column, so the engine orders it
    # NUMERICALLY. Sorting the Python side on the rendered string would disagree for a data set
    # whose sums differ in digit count.
    expected_final = sorted(
        [[cat, str(sums[cat])] for cat in kept] + [[cat, str(sums[cat])] for cat in sorted(sums)],
        key=lambda row: (row[0], int(row[1])))
    assert final_rows == expected_final, (
        f"after the INSERT the destination must hold the CTAS rows plus one row per group: "
        f"expected {expected_final!r}, got {final_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
