"""op-contract-stopQueryExecution."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-stopQueryExecution"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQueryExecution transitions a queued/running query to CANCELLED, and a
    nonexistent QueryExecutionId is rejected with InvalidRequestException."""
    output_location = _create_output_bucket(ctx)
    wg = _create_workgroup(ctx, output_location)
    athena = ctx.client("athena")

    # A cross-joined VALUES table gives the planner/execution enough real work
    # that a stop issued immediately after start reliably lands before SUCCEEDED.
    query = (
        "SELECT COUNT(*) FROM "
        "(SELECT * FROM (VALUES (1),(2),(3),(4),(5)) AS a(x)) a "
        "CROSS JOIN (SELECT * FROM (VALUES (1),(2),(3),(4),(5)) AS b(y)) b "
        "CROSS JOIN (SELECT * FROM (VALUES (1),(2),(3),(4),(5)) AS c(z)) c"
    )
    qid = athena.start_query_execution(QueryString=query, WorkGroup=wg)["QueryExecutionId"]
    athena.stop_query_execution(QueryExecutionId=qid)

    final_state = _poll_terminal(ctx, qid, timeout_s=60.0)
    assert final_state == "CANCELLED", f"expected CANCELLED, got {final_state}"

    err = _error(lambda: athena.stop_query_execution(QueryExecutionId="not-a-real-id"))
    expected = ("InvalidRequestException", "QueryExecution not-a-real-id was not found")
    assert err == expected, f"expected {expected}, got {err}"


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
        Tags=[{"Key": "sim2real", "Value": "stop-query-execution-contract"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    return wg


def _poll_terminal(ctx, qid: str, timeout_s: float = 60.0) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(1.0)
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
