"""ctas-partition-key-not-last-column-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ctas-partition-key-not-last-column-rejected"
GROUP = "query-execution"
SERVICES = ["athena"]

#: Small and uneven, so the control CTAS's per-partition layout is unambiguous and the byte
#: counts of the two partitions cannot coincide.
_ROWS = (
    ("alpha", 5),
    ("alpha", 7),
    ("beta", 40),
)


def _dataset():
    """The CSV bytes and the expected per-group amounts, from one source of truth."""
    body = "".join(f"{i},{cat},{amt}\n" for i, (cat, amt) in enumerate(_ROWS)).encode()
    groups = {}
    for cat, amt in _ROWS:
        groups.setdefault(cat, []).append(amt)
    return body, groups


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. A FAILED CTAS leaves staged data under
    `<output>/tables/<qid>/` that Athena will not delete, so the sweep is unconditional."""
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


def _start_query(athena, out, query_string, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=240, interval_s=2):
    """Poll GetQueryExecution to a terminal state with a bounded deadline; RAISES on timeout.
    Callers assert which state."""
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


def _error_code(fn):
    """The AWS error code raised by `fn`; an unexpected success raises."""
    try:
        fn()
    except Exception as exc:  # botocore ClientError and its service-specific subclasses
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if not code:
            raise AssertionError(
                f"expected a service error carrying an error code, got {exc!r}") from exc
        return code
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _keys_under(s3, bucket, prefix):
    """Every key under a prefix only this check writes, paginated."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append(obj["Key"])
    return sorted(found)


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A CTAS whose partition key is not the last SELECT column is accepted, then FAILS with
    HIVE_COLUMN_ORDER_MISMATCH, writes nothing and mints no table; with the key last it succeeds.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/create-table-as.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, groups = _dataset()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    bad = ctx.unique_name("sim2real-behav-bad-").replace("-", "_")
    good = ctx.unique_name("sim2real-behav-good-").replace("-", "_")
    # Registered BEFORE the CREATE it undoes: CASCADE drops every table, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` "
        "(`id` int, `cat` string, `amount` bigint) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    src_name = _dml_name(database, src)

    # --- break exactly ONE thing: the partition key is first in the SELECT list, not last ---
    bad_prefix = "bad/"
    bad_qid = _start_query(
        athena,
        out,
        f"CREATE TABLE {_dml_name(database, bad)} WITH (format = 'TEXTFILE', "
        f"external_location = 's3://{data_bucket}/{bad_prefix}', "
        "partitioned_by = ARRAY['cat']) AS "
        f"SELECT cat, amount FROM {src_name}",
        database=database)
    # StartQueryExecution accepts the statement; the rejection is the asynchronous terminal state.
    bad_state = _wait_terminal(athena, bad_qid)
    bad_status = athena.get_query_execution(
        QueryExecutionId=bad_qid)["QueryExecution"]["Status"]
    assert bad_state == "FAILED", (
        f"a CTAS whose partition key is not the last column of the SELECT list must reach FAILED, "
        f"got {bad_state!r} (reason {bad_status.get('StateChangeReason')!r})")

    # The reason names the broken layout rule and the offending partition key, and points at the
    # staging prefix the failed query left under the output location (keyed by the query id).
    expected_reason = (
        "HIVE_COLUMN_ORDER_MISMATCH: Partition keys must be the last columns in the table and in "
        "the same order as the table properties: [cat]. You may need to manually clean the data "
        f"at location '{out}tables/{bad_qid}' before retrying. Athena will not delete data in "
        "your account.")
    reason = bad_status["StateChangeReason"]
    assert reason == expected_reason, (
        f"the failure must name the layout rule that was broken so the customer can fix their "
        f"SQL, got {reason!r}")

    athena_error = bad_status["AthenaError"]
    assert athena_error["ErrorMessage"] == expected_reason, athena_error
    assert athena_error["ErrorCategory"] == 2, (
        f"a bad customer statement is a USER-category error (2), got "
        f"ErrorCategory={athena_error['ErrorCategory']!r}")
    assert athena_error["ErrorType"] == 1002, (
        f"real AWS classifies this as ErrorType 1002, got {athena_error['ErrorType']!r}")
    assert athena_error["Retryable"] is False, (
        f"a mis-ordered CTAS cannot succeed on retry, so Retryable must be False, got "
        f"{athena_error['Retryable']!r}")

    # --- the effect is ABSENT: nothing written, and no table minted ---
    leaked = _keys_under(s3, data_bucket, bad_prefix)
    assert leaked == [], (
        f"the rejected CTAS must write NOTHING to its destination "
        f"s3://{data_bucket}/{bad_prefix}, got {leaked!r}")
    # Only the code is asserted: the message embeds the request id of Athena's internal Glue call.
    code = _error_code(lambda: athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=database, TableName=bad))
    assert code == "MetadataException", (
        f"the table the rejected CTAS named must not exist in the catalogue; GetTableMetadata "
        f"returned {code!r}")

    # --- positive control, same file: move the key last and everything works ---
    good_prefix = "good/"
    _run_sql(
        athena, out,
        f"CREATE TABLE {_dml_name(database, good)} WITH (format = 'TEXTFILE', "
        f"external_location = 's3://{data_bucket}/{good_prefix}', "
        "partitioned_by = ARRAY['cat']) AS "
        f"SELECT amount, cat FROM {src_name}",
        database=database)
    good_keys = _keys_under(s3, data_bucket, good_prefix)
    expected_dirs = sorted(f"cat={cat}" for cat in groups)
    # Parsed on the path SEGMENT after the prefix, not by string surgery on a URI: an object
    # written at the wrong depth yields no segment and so cannot be counted as partitioned.
    got_dirs = sorted({
        seg[0] for seg in (k[len(good_prefix):].split("/") for k in good_keys)
        if len(seg) > 1 and "=" in seg[0]})
    assert got_dirs == expected_dirs, (
        f"the control CTAS must write one partition directory per distinct key value: expected "
        f"{expected_dirs!r}, got {got_dirs!r} (keys {good_keys!r})")
    assert athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=database,
        TableName=good)["TableMetadata"]["Name"] == good, (
        f"the control CTAS must mint the table {good!r} in the catalogue")

    target = min(groups, key=lambda cat: len(groups[cat]))
    control_qid = _run_sql(
        athena, out,
        f"SELECT amount FROM {_dml_name(database, good)} WHERE cat = '{target}' ORDER BY amount",
        database=database)
    control_rows = _data_rows(athena, control_qid)
    expected_rows = [[str(amt)] for amt in sorted(groups[target])]
    assert control_rows == expected_rows, (
        f"the control table must read back exactly the {target!r} group's amounts: expected "
        f"{expected_rows!r}, got {control_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
