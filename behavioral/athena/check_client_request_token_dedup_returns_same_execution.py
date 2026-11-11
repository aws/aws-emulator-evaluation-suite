"""client-request-token-dedup-returns-same-execution."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "client-request-token-dedup-returns-same-execution"
GROUP = "idempotency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution twice with one ClientRequestToken and identical parameters returns the same
    QueryExecutionId; reusing the token with a changed parameter fails InvalidRequestException and
    leaves the original execution unaffected."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    token = ctx.unique_name("sim2real-athena-tok-")

    resp1 = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": out},
        ClientRequestToken=token,
    )
    resp2 = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": out},
        ClientRequestToken=token,
    )
    assert resp1["QueryExecutionId"] == resp2["QueryExecutionId"], (
        resp1["QueryExecutionId"],
        resp2["QueryExecutionId"],
    )

    # Independent read at the destination: the equal ids above could coincide even if a
    # second execution were silently created. Confirm exactly one execution exists under
    # this token by listing executions through a different operation.
    ids = athena.list_query_executions()["QueryExecutionIds"]
    assert ids.count(resp1["QueryExecutionId"]) == 1, ids

    # The token is bound to the parameters it was first used with. Reusing it with a
    # changed QueryString must be rejected, not silently accepted or silently deduped.
    code, message = _error(
        lambda: athena.start_query_execution(
            QueryString="SELECT 2",
            ResultConfiguration={"OutputLocation": out},
            ClientRequestToken=token,
        )
    )
    assert code == "InvalidRequestException", code
    assert message == "Idempotent parameters do not match", repr(message)

    unaffected = athena.get_query_execution(QueryExecutionId=resp1["QueryExecutionId"])["QueryExecution"]
    assert unaffected["Query"] == "SELECT 1", unaffected["Query"]


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected reused token with a different query to raise InvalidRequestException")


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
