"""query-execution-lifecycle-success."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-execution-lifecycle-success"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution drives QUEUED -> ... -> SUCCEEDED and results carry the right value."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString="SELECT 101 AS answer",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/out/"},
    )["QueryExecutionId"]
    execution = _wait_for_query(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]
    assert execution["StatementType"] == "DML", f"expected StatementType=DML, got {execution['StatementType']!r}"
    assert execution["Query"] == "SELECT 101 AS answer", (
        f"expected Query to echo the submitted text, got {execution['Query']!r}"
    )

    results = athena.get_query_results(QueryExecutionId=qid)
    rows = results["ResultSet"]["Rows"]
    # SELECT queries return the column header as row 0 and the data as row 1.
    assert len(rows) == 2, f"expected header row + one data row, got {rows}"
    assert rows[0]["Data"][0]["VarCharValue"] == "answer", (
        f"expected header cell 'answer', got {rows[0]['Data'][0].get('VarCharValue')!r}"
    )
    assert rows[1]["Data"][0]["VarCharValue"] == "101", (
        f"expected data cell '101', got {rows[1]['Data'][0].get('VarCharValue')!r}"
    )
    col = results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"][0]
    assert col["Name"] == "answer", f"expected column name 'answer', got {col['Name']!r}"
    assert col["Type"] == "integer", f"expected column Type 'integer', got {col['Type']!r}"


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; this is
    # the standard idiom for CreateBucket across regions, not a region pin on the check.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "query-execution-lifecycle-success"}]},
    )

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
