"""op-contract-get-query-results-rejects-failed-query."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-get-query-results-rejects-failed-query"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults returns the exact column metadata + header/data rows for a
    SUCCEEDED query, and raises InvalidRequestException when called against a query
    that ended in FAILED state (the failed query's results are never materialized)."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)

    good_qid = athena.start_query_execution(
        QueryString="SELECT 42 AS n, 'abc' AS s",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    state = _wait_for_query(ctx, good_qid)
    assert state == "SUCCEEDED", f"setup query ended in {state}, not SUCCEEDED"

    resp = athena.get_query_results(QueryExecutionId=good_qid)
    columns = resp["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    assert [c["Name"] for c in columns] == ["n", "s"]
    rows = resp["ResultSet"]["Rows"]
    assert len(rows) == 2, f"expected header + 1 data row, got {rows}"
    assert [d.get("VarCharValue") for d in rows[0]["Data"]] == ["n", "s"]
    assert [d.get("VarCharValue") for d in rows[1]["Data"]] == ["42", "abc"]

    bad_qid = athena.start_query_execution(
        QueryString="SELECT * FROM sim2real_nonexistent_table_xyz",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    bad_state = _wait_for_query(ctx, bad_qid)
    assert bad_state == "FAILED", f"malformed query ended in {bad_state}, not FAILED"

    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Query did not finish successfully. Final query state: FAILED", (
        f"unexpected GetQueryResults message: {message!r}"
    )



def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_results_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-gqr-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "get-query-results-rejects-failed-query"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if keys:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _wait_for_query(ctx: Any, query_execution_id: str, timeout_s: float = 90.0) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(2)
    raise AssertionError(f"query {query_execution_id} stuck in {state} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
