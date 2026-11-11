"""op-contract-batch-get-query-execution."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-batch-get-query-execution"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetQueryExecution returns full execution details (query text, terminal
    state, data-scanned stats) for real execution ids and reports unknown ids under
    UnprocessedQueryExecutionIds instead of raising."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)

    qeids = []
    for i in range(2):
        qid = athena.start_query_execution(
            QueryString=f"SELECT {i} AS n",
            ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
        )["QueryExecutionId"]
        qeids.append(qid)
    for qid in qeids:
        state = _wait_for_query(ctx, qid, timeout_s=90)
        assert state == "SUCCEEDED", f"query {qid} ended in {state}, not SUCCEEDED"

    bogus_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    resp = athena.batch_get_query_execution(QueryExecutionIds=qeids + [bogus_id])

    returned = {qe["QueryExecutionId"]: qe for qe in resp["QueryExecutions"]}
    assert set(returned) == set(qeids), f"expected {qeids}, got {list(returned)}"
    for i, qid in enumerate(qeids):
        qe = returned[qid]
        assert qe["Query"] == f"SELECT {i} AS n"
        assert qe["Status"]["State"] == "SUCCEEDED"
        scanned = qe["Statistics"]["DataScannedInBytes"]
        assert scanned == 0, f"literal-only query should scan 0 bytes, got {scanned}"

    unprocessed = resp["UnprocessedQueryExecutionIds"]
    assert len(unprocessed) == 1, f"expected 1 unprocessed id, got {unprocessed}"
    assert unprocessed[0]["QueryExecutionId"] == bogus_id
    assert unprocessed[0]["ErrorCode"] == "QUERY_EXECUTION_NOT_FOUND", (
        f"expected QUERY_EXECUTION_NOT_FOUND for unknown execution id, got {unprocessed[0]['ErrorCode']!r}"
    )


def _create_results_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-bgqe-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
