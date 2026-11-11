"""athena-query-execution-syntax-error-failed-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-query-execution-syntax-error-failed-state"
GROUP = "state"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query on a nonexistent schema reaches FAILED with a user-category SCHEMA_NOT_FOUND error,
    and GetQueryResults on it is refused, while SELECT 1 to the same output location succeeds."""
    bucket = _create_result_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/results/"

    # A valid query first, so the failure below is the semantic error and not a broken setup.
    control_qid = athena.start_query_execution(
        QueryString="SELECT 1", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    control = _wait_query_terminal(ctx, control_qid, timeout_s=60)
    assert control["Status"]["State"] == "SUCCEEDED", (
        f"expected the control query to succeed, got {control['Status']}"
    )

    # A syntax typo is rejected synchronously by StartQueryExecution; a missing schema is only
    # caught during asynchronous planning, so it yields an execution that reaches FAILED.
    missing_schema = "sim2real_nonexistent_db_9f3c1a"
    qid = athena.start_query_execution(
        QueryString=f"SELECT * FROM {missing_schema}.sim2real_nonexistent_table_9f3c1a",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]

    qe = _wait_query_terminal(ctx, qid, timeout_s=60)
    assert qe["Status"]["State"] == "FAILED", f"expected FAILED, got {qe['Status']}"
    athena_error = qe["Status"]["AthenaError"]
    assert athena_error["ErrorCategory"] == 2, (  # 2 == USER error (bad SQL), not a system error
        f"expected USER error category (2), got {athena_error['ErrorCategory']}"
    )
    expected_reason = f"SCHEMA_NOT_FOUND: line 1:15: Schema '{missing_schema}' does not exist"
    assert athena_error["ErrorMessage"] == expected_reason, (
        f"unexpected AthenaError.ErrorMessage: {athena_error['ErrorMessage']!r}"
    )
    assert qe["Status"]["StateChangeReason"] == expected_reason, (
        f"unexpected StateChangeReason: {qe['Status']['StateChangeReason']!r}"
    )

    # The failed query never produced a readable result set.
    from botocore.exceptions import ClientError

    try:
        athena.get_query_results(QueryExecutionId=qid)
        raise AssertionError("expected GetQueryResults on a FAILED query to raise")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
        assert message == "Query did not finish successfully. Final query state: FAILED", (
            f"unexpected GetQueryResults refusal message: {message!r}"
        )


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-res-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
        time.sleep(2.0)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
