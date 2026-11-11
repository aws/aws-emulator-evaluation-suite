"""athena-start-query-execution-client-request-token-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-start-query-execution-client-request-token-idempotent"
GROUP = "idempotency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution with a reused ClientRequestToken+params returns the SAME QueryExecutionId."""
    bucket = _create_result_bucket(ctx)
    athena = ctx.client("athena")
    token = ctx.unique_name("sim2real-athena-token-")
    output = f"s3://{bucket}/results/"

    first = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": output},
        ClientRequestToken=token,
    )["QueryExecutionId"]

    second = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": output},
        ClientRequestToken=token,
    )["QueryExecutionId"]
    assert second == first, f"expected reused token+params to replay the same execution id, got first={first} second={second}"

    ids = athena.list_query_executions()["QueryExecutionIds"]
    assert ids.count(first) == 1, f"expected exactly one listed execution for {first}, got {ids.count(first)} in {ids}"

    # Same token + a DIFFERENT query string -> rejected, no new execution created under that id space.
    from botocore.exceptions import ClientError

    try:
        athena.start_query_execution(
            QueryString="SELECT 2",
            ResultConfiguration={"OutputLocation": output},
            ClientRequestToken=token,
        )
        raise AssertionError("expected reused token with a different query to raise InvalidRequestException")
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        expected = ("InvalidRequestException", "Idempotent parameters do not match")
        assert err == expected, f"expected {expected}, got {err}"

    # Effect-absent: the rejected call must not have touched the execution the token already owns.
    unaffected = athena.get_query_execution(QueryExecutionId=first)["QueryExecution"]
    assert unaffected["Query"] == "SELECT 1", f"expected original execution's query unchanged, got {unaffected['Query']!r}"


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-res-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
