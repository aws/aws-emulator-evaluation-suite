"""ctas-creates-queryable-table."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ctas-creates-queryable-table"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CREATE TABLE AS SELECT (CTAS) materializes real data in S3, and a subsequent
    SELECT against the new table returns the exact values that were written."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    db = ctx.unique_name("sim2real_athena_ctasdb_").replace("-", "_")
    tbl = ctx.unique_name("sim2real_athena_tbl_").replace("-", "_")

    qid = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db} LOCATION 's3://{bucket}/db/'",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    created_db = _wait_for_query(ctx, qid)
    assert created_db["Status"]["State"] == "SUCCEEDED", created_db["Status"]

    def _drop_db():
        _wait_for_query(
            ctx,
            athena.start_query_execution(
                QueryString=f"DROP DATABASE {db} CASCADE",
                ResultConfiguration={"OutputLocation": out},
            )["QueryExecutionId"],
        )

    ctx.on_cleanup(_drop_db)

    ctas_sql = (
        f"CREATE TABLE {db}.{tbl} "
        f"WITH (format='PARQUET', external_location='s3://{bucket}/ctas/{tbl}/') "
        "AS SELECT 42 AS num, 'hello' AS txt"
    )
    qid2 = athena.start_query_execution(
        QueryString=ctas_sql, ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    ctas_exec = _wait_for_query(ctx, qid2)
    assert ctas_exec["Status"]["State"] == "SUCCEEDED", ctas_exec["Status"]
    # CTAS is a CREATE TABLE statement; Athena classifies it as DDL (not DML),
    # even though it also materializes data via the embedded SELECT.
    assert ctas_exec["StatementType"] == "DDL", ctas_exec["StatementType"]

    qid3 = athena.start_query_execution(
        QueryString=f"SELECT num, txt FROM {db}.{tbl}",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    select_exec = _wait_for_query(ctx, qid3)
    assert select_exec["Status"]["State"] == "SUCCEEDED", select_exec["Status"]
    results = athena.get_query_results(QueryExecutionId=qid3)
    row = results["ResultSet"]["Rows"][1]["Data"]
    assert row[0]["VarCharValue"] == "42", f"expected num=42, got {row[0]}"
    assert row[1]["VarCharValue"] == "hello", f"expected txt='hello', got {row[1]}"


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        while objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
            resp = s3.list_objects_v2(Bucket=bucket)
            objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_query(ctx, qid, timeout_s=180.0, interval_s=2.0):
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)
        last = resp["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(interval_s)
    state = last["Status"]["State"] if last else None
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
