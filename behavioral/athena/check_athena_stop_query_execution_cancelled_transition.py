"""athena-stop-query-execution-cancelled-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-stop-query-execution-cancelled-transition"
GROUP = "state"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQueryExecution on a running query drives QueryExecutionState to CANCELLED."""
    bucket = _create_result_bucket(ctx)
    athena = ctx.client("athena")

    # A heavy cross join gives StopQueryExecution a real window before natural completion.
    heavy_query = (
        "SELECT count(*) FROM UNNEST(SEQUENCE(1, 10000)) AS a(x) "
        "CROSS JOIN UNNEST(SEQUENCE(1, 10000)) AS b(y)"
    )
    qid = athena.start_query_execution(
        QueryString=heavy_query,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    athena.stop_query_execution(QueryExecutionId=qid)

    qe = _wait_query_terminal(ctx, qid, timeout_s=60)
    assert qe["Status"]["State"] == "CANCELLED", (
        f"expected CANCELLED after StopQueryExecution, got {qe['Status']}"
    )


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-res-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "stop-query-execution-cancelled-transition"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_query_terminal(ctx, query_execution_id: str, timeout_s: float = 60.0) -> dict:
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(1.5)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
