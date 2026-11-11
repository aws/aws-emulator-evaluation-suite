"""athena-get-query-results-not-finished-error."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-get-query-results-not-finished-error"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults on a still-running query raises InvalidRequestException; succeeds once terminal."""
    bucket = _create_result_bucket(ctx)
    athena = ctx.client("athena")

    heavy_query = (
        "SELECT count(*) FROM UNNEST(SEQUENCE(1, 10000)) AS a(x) "
        "CROSS JOIN UNNEST(SEQUENCE(1, 10000)) AS b(y)"
    )
    qid = athena.start_query_execution(
        QueryString=heavy_query,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    from botocore.exceptions import ClientError

    # The refusal names the query's current state, so the state is read on both sides of the
    # GetQueryResults call; a transition inside that window is retried so the expected message is
    # built from a state that held for the whole call. A target that finished the query before
    # the first read serves its results instead, and that answer is graded.
    for _ in range(5):
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state not in ("QUEUED", "RUNNING"):
            break
        code = message = None
        try:
            athena.get_query_results(QueryExecutionId=qid)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
        state_after = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state_after == state:
            break
    else:
        raise AssertionError(f"query state never held still across one GetQueryResults call (last {state_after})")
    if state in ("QUEUED", "RUNNING"):
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
        expected = f"Query has not yet finished. Current state: {state}"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        athena.stop_query_execution(QueryExecutionId=qid)
        _wait_query_terminal(ctx, qid, timeout_s=60)
    else:
        assert state == "SUCCEEDED", f"expected the cross join to succeed, got {state}"
        rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
        count = rows[1]["Data"][0]["VarCharValue"]
        assert count == "100000000", f"expected the cross join to count 100000000 rows, got {count!r}"

    # Positive control: a completed, trivial query's results ARE readable.
    fast_qid = athena.start_query_execution(
        QueryString="SELECT 42 AS answer",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    qe = _wait_query_terminal(ctx, fast_qid, timeout_s=60)
    assert qe["Status"]["State"] == "SUCCEEDED", f"expected SUCCEEDED, got {qe['Status']['State']}"
    rows = athena.get_query_results(QueryExecutionId=fast_qid)["ResultSet"]["Rows"]
    got = rows[1]["Data"][0]["VarCharValue"]
    assert got == "42", f"expected literal result '42', got {got!r}"


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-res-")
    # us-east-1 rejects an explicit LocationConstraint matching the default region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
