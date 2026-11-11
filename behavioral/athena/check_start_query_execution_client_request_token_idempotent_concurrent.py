"""start-query-execution-client-request-token-idempotent-concurrent."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "start-query-execution-client-request-token-idempotent-concurrent"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Firing several concurrent StartQueryExecution calls that share the same
    ClientRequestToken deduplicates to a single QueryExecutionId (idempotency under
    contention); a call with a different token gets a distinct, unrelated id."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    query = "SELECT 'idempotency-race' AS marker"
    out_loc = {"OutputLocation": f"s3://{bucket}/results/"}
    # StartQueryExecution's ClientRequestToken enforces a minimum length of 32
    # characters; ctx.unique_name's default output is shorter than that.
    token = f"sim2real-token-{uuid.uuid4().hex}"

    def _start():
        return athena.start_query_execution(
            QueryString=query, ResultConfiguration=out_loc, ClientRequestToken=token
        )["QueryExecutionId"]

    with ThreadPoolExecutor(max_workers=5) as pool:
        ids = list(pool.map(lambda _: _start(), range(5)))

    assert len(set(ids)) == 1, f"expected a single deduplicated id, got {set(ids)}"
    shared_qid = ids[0]

    other_token = f"sim2real-token-other-{uuid.uuid4().hex}"
    other_qid = athena.start_query_execution(
        QueryString=query, ResultConfiguration=out_loc, ClientRequestToken=other_token
    )["QueryExecutionId"]
    assert other_qid != shared_qid

    # Terminal assertion is an independent read (GetQueryExecution), not the
    # StartQueryExecution responses already compared above: the dedup only counts
    # if the shared id actually ran to a real, queryable result.
    shared_final = _poll_query_execution(ctx, shared_qid)
    other_final = _poll_query_execution(ctx, other_qid)
    for qid, final in ((shared_qid, shared_final), (other_qid, other_final)):
        state = final["Status"]["State"]
        assert state == "SUCCEEDED", f"query {qid} expected SUCCEEDED, got {state}"

    ids_seen = athena.list_query_executions()["QueryExecutionIds"]
    assert ids_seen.count(shared_qid) == 1, (
        f"expected the deduplicated id to appear exactly once in ListQueryExecutions, "
        f"got {ids_seen.count(shared_qid)}"
    )
    assert other_qid in ids_seen, f"expected {other_qid} to be listed, got {ids_seen}"


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "start-query-execution-client-request-token-idempotent-concurrent"},
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
