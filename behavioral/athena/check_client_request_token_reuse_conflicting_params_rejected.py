"""client-request-token-reuse-conflicting-params-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "client-request-token-reuse-conflicting-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with a different QueryString is rejected with
    InvalidRequestException, and the original query execution (submitted under that
    token) is left completely unaffected (positive control)."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    token = ctx.unique_name("sim2real-athena-tok-")

    first_id = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": out},
        ClientRequestToken=token,
    )["QueryExecutionId"]

    code, message = _error(
        lambda: athena.start_query_execution(
            QueryString="SELECT 2",
            ResultConfiguration={"OutputLocation": out},
            ClientRequestToken=token,
        )
    )
    assert code == "InvalidRequestException", code
    assert message == "Idempotent parameters do not match", repr(message)

    unchanged = athena.get_query_execution(QueryExecutionId=first_id)["QueryExecution"]
    assert unchanged["Query"] == "SELECT 1", unchanged["Query"]


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the reused token with a different query to be rejected, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})

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
