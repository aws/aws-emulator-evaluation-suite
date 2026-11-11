"""concurrent-query-executions-all-succeed."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-query-executions-all-succeed"
GROUP = "concurrency"
SERVICES = ["athena"]

#: The DML concurrency quota is per-account and shared with anything else running in the
#: account, so a ThrottlingException on StartQueryExecution is an environment condition, not
#: a failed execution.
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N distinct queries fired concurrently each get their own distinct
    QueryExecutionId, all reach SUCCEEDED, and each returns exactly its own value
    (no cross-talk between concurrent executions)."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    n = 5

    def _submit_and_wait(i):
        qid = _start_with_throttle_retry(athena, f"SELECT {i} AS n", out)
        execution = _wait_for_query(ctx, qid)
        results = athena.get_query_results(QueryExecutionId=qid)
        value = int(results["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"])
        return qid, execution["Status"]["State"], value

    with ThreadPoolExecutor(max_workers=n) as pool:
        outcomes = list(pool.map(_submit_and_wait, range(n)))

    qids = [o[0] for o in outcomes]
    assert len(set(qids)) == n, qids  # every racer got a distinct execution id
    for i, (qid, state, value) in enumerate(outcomes):
        assert state == "SUCCEEDED", (i, state)
        assert value == i, (i, value)  # no cross-talk: query i's result is exactly i


def _start_with_throttle_retry(athena, query_string, out):
    """StartQueryExecution with a bounded backoff over the throttle codes only.

    A ThrottlingException must be retried, not counted as a failed execution: the per-account DML
    concurrency quota is shared with every other workload running in the same account. Any
    OTHER ClientError is re-raised immediately — swallowing it would turn a real fidelity failure
    into a timeout.
    """
    last = None
    for attempt in range(6):
        try:
            return athena.start_query_execution(
                QueryString=query_string,
                ResultConfiguration={"OutputLocation": out},
            )["QueryExecutionId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = code
            time.sleep(2 * (attempt + 1))
    raise AssertionError(f"StartQueryExecution stayed throttled ({last!r}) across 6 attempts")


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "concurrent-query-executions-all-succeed"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

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
