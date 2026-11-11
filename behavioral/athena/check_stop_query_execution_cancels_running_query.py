"""stop-query-execution-cancels-running-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stop-query-execution-cancels-running-query"
GROUP = "query-execution"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Calling StopQueryExecution shortly after StartQueryExecution on a query that is still
    queued/running transitions it to the terminal CANCELLED state (not SUCCEEDED/FAILED)."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    # A moderately heavy in-memory computation gives StopQueryExecution a real window to land
    # before the query would otherwise reach SUCCEEDED.
    qid = athena.start_query_execution(
        QueryString="SELECT count(*) FROM UNNEST(SEQUENCE(0, 20000000)) AS t(x)",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    athena.stop_query_execution(QueryExecutionId=qid)

    execution = _poll_query_execution(ctx, qid, timeout_s=90.0)
    assert execution["Status"]["State"] == "CANCELLED", execution["Status"]


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "stop-query-execution-cancels-running-query"},
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
