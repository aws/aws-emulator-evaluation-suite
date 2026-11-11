"""query-execution-syntax-error-fails-with-athena-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-execution-syntax-error-fails-with-athena-error"
GROUP = "error-semantics"
SERVICES = ["athena"]

#: The statement keywords the engine's parser lists after a mismatched first token, verbatim.
_EXPECTING = (
    "'ALTER', 'ANALYZE', 'CALL', 'COMMENT', 'COMMIT', 'CREATE', 'DEALLOCATE', 'DELETE', 'DENY', "
    "'DESC', 'DESCRIBE', 'DROP', 'EXECUTE', 'EXPLAIN', 'GRANT', 'INSERT', 'MERGE', 'PREPARE', "
    "'REFRESH', 'RESET', 'REVOKE', 'ROLLBACK', 'SET', 'SHOW', 'START', 'TRUNCATE', 'UNLOAD', "
    "'UPDATE', 'USE', <query>"
)


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution rejects invalid SQL synchronously with InvalidRequestException and the
    parser's message, rather than a later FAILED state; valid SQL in the same call succeeds."""
    from botocore.exceptions import ClientError

    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/results/"

    try:
        athena.start_query_execution(
            QueryString="SELCET 1 FORM nowhere",
            ResultConfiguration={"OutputLocation": out},
        )
        raise AssertionError("expected StartQueryExecution to reject the malformed query synchronously")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
        assert message == f"line 1:1: mismatched input 'SELCET'. Expecting: {_EXPECTING}", (
            f"unexpected parser error message: {message!r}"
        )

    # Positive control: the same wiring accepts syntactically valid SQL.
    qid = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    assert qid, "expected a syntactically valid query to be accepted and minted a QueryExecutionId"


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

