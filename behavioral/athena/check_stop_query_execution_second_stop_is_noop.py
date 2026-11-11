"""stop-query-execution-second-stop-is-noop."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "stop-query-execution-second-stop-is-noop"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQueryExecution ends an in-flight query CANCELLED, and a second StopQueryExecution
    against that same already-terminal execution is idempotent: it does not raise, and it does
    not mutate the execution's state again."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)

    heavy_query = (
        "SELECT COUNT(*) FROM UNNEST(SEQUENCE(1, 20000)) AS a(x) "
        "CROSS JOIN UNNEST(SEQUENCE(1, 20000)) AS b(y) "
        "WHERE x % 97 = 0 AND y % 89 = 0"
    )
    qid = athena.start_query_execution(
        QueryString=heavy_query,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    # The state read right before the first stop decides what it is graded on: an in-flight
    # query must end CANCELLED; one already terminal leaves the cancel itself ungraded.
    pre_stop_state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
    if pre_stop_state not in ("QUEUED", "RUNNING"):
        raise TimeoutError(
            f"the heavy query was already {pre_stop_state} before the first stop; the cancel of an "
            "in-flight query is not graded"
        )
    athena.stop_query_execution(QueryExecutionId=qid)
    final_state = _wait_for_query(ctx, qid, timeout_s=90)
    assert final_state == "CANCELLED", (
        f"expected the query read {pre_stop_state} before the stop to end CANCELLED, got {final_state}"
    )

    # A second StopQueryExecution on the terminal execution is a no-op: it does not raise, and
    # it leaves the execution's terminal state unchanged.
    athena.stop_query_execution(QueryExecutionId=qid)
    state_after_second_stop = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
    assert state_after_second_stop == final_state, (
        f"expected the no-op second stop to leave the execution {final_state}, got {state_after_second_stop}"
    )


def _create_results_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-stop-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # CreateBucket rejects an explicit LocationConstraint of us-east-1; every other
    # region requires it. Not a region pin — ctx.region drives the bucket itself.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "stop-query-execution-second-stop-is-noop"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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
        time.sleep(1.5)
    raise AssertionError(f"query {query_execution_id} stuck in {state} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
