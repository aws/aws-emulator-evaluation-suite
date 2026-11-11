"""op-contract-getQueryResults."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-getQueryResults"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults returns the exact column metadata and row data for a
    completed SELECT, and rejects a nonexistent QueryExecutionId with
    InvalidRequestException rather than returning empty results."""
    output_location = _create_output_bucket(ctx)
    wg = _create_workgroup(ctx, output_location)
    athena = ctx.client("athena")

    query = "SELECT 1 AS col"
    qid, state, _ = _run_query_and_wait(ctx, query, wg)
    assert state == "SUCCEEDED", f"expected setup query to SUCCEED, got {state}"

    results = athena.get_query_results(QueryExecutionId=qid)
    columns = results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    assert len(columns) == 1, f"expected exactly 1 column, got {len(columns)}: {columns}"
    assert columns[0]["Name"] == "col", f"expected column name 'col', got {columns[0]['Name']!r}"
    rows = results["ResultSet"]["Rows"]
    assert len(rows) == 2, f"expected header row + one data row, got {len(rows)}: {rows}"
    assert rows[0]["Data"][0]["VarCharValue"] == "col", f"expected header 'col', got {rows[0]['Data'][0]}"
    assert rows[1]["Data"][0]["VarCharValue"] == "1", f"expected data value '1', got {rows[1]['Data'][0]}"

    # Negative: a nonexistent QueryExecutionId is rejected, not silently empty.
    unknown_qid = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=unknown_qid))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"QueryExecution {unknown_qid} was not found", (
        f"unexpected GetQueryResults message: {message!r}"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower()
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other
    # region requires it. Not a region pin on the check itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "get-query-results-rejects-unknown-execution"},
    ]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return f"s3://{bucket}/"


def _create_workgroup(ctx, output_location: str) -> str:
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": output_location}},
        Tags=[{"Key": "sim2real", "Value": "get-query-results-rejects-unknown-execution"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    return wg


def _run_query_and_wait(ctx, query: str, workgroup: str, timeout_s: float = 120.0):
    athena = ctx.client("athena")
    qid = athena.start_query_execution(QueryString=query, WorkGroup=workgroup)["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    resp = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, resp
        time.sleep(1.5)
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected InvalidRequestException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
