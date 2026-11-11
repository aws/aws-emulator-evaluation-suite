"""batch-get-query-execution-reflects-started-queries."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-query-execution-reflects-started-queries"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetQueryExecution returns the exact Query text and WorkGroup for each of
    several distinct QueryExecutionIds started earlier."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"

    qid1 = athena.start_query_execution(
        QueryString="SELECT 1", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    qid2 = athena.start_query_execution(
        QueryString="SELECT 2", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    _wait_for_query(ctx, qid1)
    _wait_for_query(ctx, qid2)

    resp = athena.batch_get_query_execution(QueryExecutionIds=[qid1, qid2])
    by_id = {e["QueryExecutionId"]: e for e in resp["QueryExecutions"]}
    assert set(by_id) == {qid1, qid2}, f"expected {{qid1, qid2}}, got {set(by_id)}"
    assert by_id[qid1]["Query"] == "SELECT 1", f"expected 'SELECT 1' for {qid1}, got {by_id[qid1]['Query']!r}"
    assert by_id[qid2]["Query"] == "SELECT 2", f"expected 'SELECT 2' for {qid2}, got {by_id[qid2]['Query']!r}"
    assert by_id[qid1]["Status"]["State"] == "SUCCEEDED", f"expected SUCCEEDED for {qid1}, got {by_id[qid1]['Status']['State']}"
    assert by_id[qid2]["Status"]["State"] == "SUCCEEDED", f"expected SUCCEEDED for {qid2}, got {by_id[qid2]['Status']['State']}"
    assert resp["UnprocessedQueryExecutionIds"] == [], f"expected no unprocessed ids, got {resp['UnprocessedQueryExecutionIds']}"


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
