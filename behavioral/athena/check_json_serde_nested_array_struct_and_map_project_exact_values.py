"""json-serde-nested-array-struct-and-map-project-exact-values."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "json-serde-nested-array-struct-and-map-project-exact-values"
GROUP = "query-execution"
SERVICES = ["athena"]

#: Two records with DIFFERENT array lengths, a negative struct member and a map whose keys differ
#: between rows, so a target that returns a constant row, echoes the raw JSON text, or flattens
#: every nested value to the same shape cannot coincide with the right answer.
_RECORDS = (
    {"id": 1, "tags": ["red", "green", "blue"], "meta": {"k": "alpha", "v": 10},
     "kv": {"a": 1, "b": 2}},
    {"id": 2, "tags": ["solo"], "meta": {"k": "beta", "v": -3}, "kv": {"a": 7}},
)


def _dataset():
    """The newline-delimited JSON bytes and the expected projection, from one source of truth."""
    body = ("\n".join(json.dumps(r) for r in _RECORDS) + "\n").encode()
    expected = [
        [str(r["id"]), r["tags"][0], str(len(r["tags"])), r["meta"]["k"], str(r["meta"]["v"]),
         str(r["kv"]["a"])]
        for r in sorted(_RECORDS, key=lambda r: r["id"])
    ]
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
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:].
    Returned as a LIST: ORDER BY makes the order a server-side guarantee."""
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
    """The JSON SerDe deserialises nested JSON: an array<string> is indexed and sized per row, a
    struct member keeps a negative int, a map is subscripted by key, all matching the uploaded data,
    and the scan reads exactly the uploaded bytes.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/json-serde.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, expected = _dataset()
    s3.put_object(Bucket=data_bucket, Key="json/rows.json", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-js-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops the table too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` ("
        "`id` int, `tags` array<string>, "
        "`meta` struct<`k`:string,`v`:int>, `kv` map<string,int>) "
        "ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe' "
        f"LOCATION 's3://{data_bucket}/json/'")

    table_name = _dml_name(database, table)

    # --- leg 1: project INSIDE each nested type and compare to the Python-computed values.
    #     Trino array indexing is 1-based, so tags[1] is the first element.
    proj_qid = _run_sql(
        athena, out,
        "SELECT id, tags[1] AS first_tag, cardinality(tags) AS n_tags, meta.k AS meta_k, "
        f"meta.v AS meta_v, kv['a'] AS kv_a FROM {table_name} ORDER BY id",
        database=database)
    proj = _result_set(athena, proj_qid)
    rows = _data_rows(proj)
    assert rows == expected, (
        f"projecting inside the array, struct and map must yield the values computed from the "
        f"{len(_RECORDS)} uploaded JSON records: expected {expected!r}, got {rows!r}")

    scanned = _scanned(athena, proj_qid)
    assert scanned == len(body), (
        f"the projection must have been computed over the {len(body)} bytes this check uploaded, "
        f"not fabricated: DataScannedInBytes was {scanned!r}")

    # --- leg 2: the engine's own type for each projected nested value. A client reading the
    #     result through JDBC has nothing else to go on, so a wrong type is a real defect.
    types = [(c["Name"], c["Type"]) for c in proj["ResultSetMetadata"]["ColumnInfo"]]
    assert types == [("id", "integer"), ("first_tag", "varchar"), ("n_tags", "bigint"),
                     ("meta_k", "varchar"), ("meta_v", "integer"), ("kv_a", "integer")], (
        f"the projected nested values must carry the engine's types — cardinality() is bigint "
        f"while the struct's `int` member stays integer — got {types!r}")

    # --- leg 3: the whole array as a value. This rendering is what lands in the result CSV, so
    #     it is the only form a non-Athena consumer of the output object ever sees.
    whole_qid = _run_sql(
        athena, out, f"SELECT id, tags FROM {table_name} ORDER BY id", database=database)
    whole = _result_set(athena, whole_qid)
    whole_rows = _data_rows(whole)
    expected_whole = [
        [str(r["id"]), "[" + ", ".join(r["tags"]) + "]"]
        for r in sorted(_RECORDS, key=lambda r: r["id"])]
    assert whole_rows == expected_whole, (
        f"an array projected whole must render as its bracketed comma-joined elements: expected "
        f"{expected_whole!r}, got {whole_rows!r}")
    whole_types = [(c["Name"], c["Type"]) for c in whole["ResultSetMetadata"]["ColumnInfo"]]
    assert whole_types == [("id", "integer"), ("tags", "array")], (
        f"a whole-array column must be typed `array` in the result metadata, got {whole_types!r}")

    # --- leg 4: the nested values really discriminate between rows. Filtering on a map value
    #     server-side must return only the row whose map holds it.
    wanted = _RECORDS[1]["kv"]["a"]
    others = {r["kv"]["a"] for r in _RECORDS} - {wanted}
    # A FIXTURE guard, not an assertion about the target: the filter must be selective, or the
    # leg would pass for any target that returns every row.
    assert others and wanted not in others, (
        f"_RECORDS no longer gives kv['a'] a unique value to filter on: {others!r} vs {wanted!r}")
    filtered_qid = _run_sql(
        athena, out,
        f"SELECT id FROM {table_name} WHERE kv['a'] = {wanted} ORDER BY id", database=database)
    filtered = _data_rows(_result_set(athena, filtered_qid))
    assert filtered == [[str(_RECORDS[1]["id"])]], (
        f"filtering on the map value {wanted} must return only record "
        f"{_RECORDS[1]['id']}, got {filtered!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
