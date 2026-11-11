"""query-execution-external-table-s3-roundtrip."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "query-execution-external-table-s3-roundtrip"
GROUP = "query-execution"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CREATE EXTERNAL TABLE over a CSV object placed in S3, then SELECT, returns the exact
    rows that were uploaded (Athena really scans the S3 data, not a mock), and DROP TABLE makes
    the table unreadable, unlisted and unwritable afterwards. The database is the check's own."""
    bucket = _create_results_bucket(ctx)
    s3 = ctx.client("s3")
    athena = ctx.client("athena")
    table = ctx.unique_name("sim2real_athena_tbl_").replace("-", "_")
    database = ctx.unique_name("sim2real_athena_db_").replace("-", "_")
    output = {"OutputLocation": f"s3://{bucket}/results/"}
    data_prefix = f"data/{table}/"
    # A per-run marker in the string column: an emulator that returns a fixed id/name
    # ResultSet for every query cannot fabricate this row.
    marker = ctx.unique_name("").replace("-", "")[:12]
    body = f"10,foo-{marker}\n20,bar-{marker}\n30,baz-{marker}\n".encode()
    s3.put_object(Bucket=bucket, Key=f"{data_prefix}part-0.csv", Body=body)

    # A check-owned database, not the account's "default" one.
    db_exec = _run_query(ctx, f"CREATE DATABASE {database}", output)
    # CREATE DATABASE touches no table, no S3 data and no syntax question: the only way it does not
    # SUCCEED is that no SQL engine executed it.
    assert db_exec["Status"]["State"] == "SUCCEEDED", (
        f"DATAPLANE_UNIMPLEMENTED: CREATE DATABASE {database} did not SUCCEED, so no SQL engine "
        f"executed it: {db_exec['Status']!r}"
    )
    ctx.on_cleanup(lambda: _run_teardown_query(ctx, f"DROP DATABASE IF EXISTS {database} CASCADE", output))

    ddl_qid = athena.start_query_execution(
        QueryString=(
            f"CREATE EXTERNAL TABLE {database}.{table} (id INT, name STRING) "
            "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' "
            f"LOCATION 's3://{bucket}/{data_prefix}'"
        ),
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    ddl_exec = _poll_query_execution(ctx, ddl_qid)
    assert ddl_exec["Status"]["State"] == "SUCCEEDED", ddl_exec["Status"]

    def _drop_table():
        _run_teardown_query(ctx, f"DROP TABLE IF EXISTS {database}.{table}", output)

    ctx.on_cleanup(_drop_table)

    select_qid = athena.start_query_execution(
        QueryString=f"SELECT id, name FROM {database}.{table} ORDER BY id",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    select_exec = _poll_query_execution(ctx, select_qid)
    assert select_exec["Status"]["State"] == "SUCCEEDED", select_exec["Status"]

    results = athena.get_query_results(QueryExecutionId=select_qid)
    rows = results["ResultSet"]["Rows"]
    values = [[c.get("VarCharValue") for c in r["Data"]] for r in rows]
    assert values == [
        ["id", "name"],
        ["10", f"foo-{marker}"],
        ["20", f"bar-{marker}"],
        ["30", f"baz-{marker}"],
    ], values

    # bytes were genuinely read off S3 for this SELECT -- a fabricated ResultSet scans nothing
    scanned = select_exec["Statistics"]["DataScannedInBytes"]
    assert scanned > 0, f"scan of {len(body)} real CSV bytes must be > 0, got {scanned}"

    # --- DROP TABLE really removes it: an INDEPENDENT read now fails, not just the drop's own 200 ---
    _drop_table()
    from botocore.exceptions import ClientError

    # Gone beat 1: the catalog read by name is refused.
    try:
        athena.get_table_metadata(CatalogName="AwsDataCatalog", DatabaseName=database, TableName=table)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = exc.response["Error"].get("Message") or ""
    else:
        raise AssertionError(f"GetTableMetadata still returns the dropped table {table}")
    assert code == "MetadataException", f"expected MetadataException for the dropped table, got {code}"
    assert status == 400, f"expected HTTP 400 for GetTableMetadata of the dropped table, got {status}"
    message_head, _, request_id = message.partition("; Request ID: ")
    expected_message = "Entity Not Found (Service: AmazonDataCatalog; Status Code: 400; Error Code: EntityNotFoundException"
    assert message_head == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}; Proxy: null\)", request_id), f"unexpected request id in {message!r}"

    # Gone beat 2: the database's table listing no longer holds it.
    listed = [
        t["Name"]
        for page in athena.get_paginator("list_table_metadata").paginate(
            CatalogName="AwsDataCatalog", DatabaseName=database
        )
        for t in page["TableMetadataList"]
    ]
    assert table not in listed, f"ListTableMetadata still lists the dropped table: {listed!r}"

    # A read and a write against the dropped table both fail as a user error. The SELECT's
    # StateChangeReason names the missing table; the INSERT's reason is graded non-empty only.
    for sql, names_table in (
        (f"SELECT * FROM {database}.{table}", True),
        (f"INSERT INTO {database}.{table} VALUES (40, 'qux')", False),
    ):
        failed = _run_query(ctx, sql, output)
        assert failed["Status"]["State"] == "FAILED", f"{sql!r} against the dropped table: {failed['Status']!r}"
        err = failed["Status"].get("AthenaError") or {}
        assert err.get("ErrorCategory") == 2, f"expected a USER (2) AthenaError for {sql!r}, got {err!r}"
        assert isinstance(err.get("ErrorType"), int), f"expected an AthenaError ErrorType for {sql!r}, got {err!r}"
        reason = failed["Status"].get("StateChangeReason") or ""
        assert reason.strip(), f"expected a non-empty StateChangeReason for {sql!r}, got {failed['Status']!r}"
        if names_table:
            assert table in reason, (
                f"expected the StateChangeReason for {sql!r} to name the dropped table, got {reason!r}"
            )


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":  # CreateBucketConfiguration is REJECTED for us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    def _cleanup():
        token = None
        while True:
            kw = {"Bucket": bucket}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _run_query(ctx, sql, output):
    """Start one query and poll it to a terminal state."""
    qid = ctx.client("athena").start_query_execution(QueryString=sql, ResultConfiguration=output)[
        "QueryExecutionId"
    ]
    return _poll_query_execution(ctx, qid)


def _run_teardown_query(ctx, sql, output):
    """A teardown DDL that must SUCCEED; a FAILED drop would leak the Glue database/table."""
    resp = _run_query(ctx, sql, output)
    if resp["Status"]["State"] != "SUCCEEDED":
        raise AssertionError(f"teardown query {sql!r} did not succeed: {resp['Status']!r}")
    return resp


def _poll_query_execution(ctx, qid, timeout_s=120.0, interval_s=1.5):
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        last = resp
        if resp["Status"]["State"] in terminal:
            return resp
        time.sleep(interval_s)
    state = last["Status"]["State"] if last else "?"
    raise AssertionError(f"query {qid} stuck in {state} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
