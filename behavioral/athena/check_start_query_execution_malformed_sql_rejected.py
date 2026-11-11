"""start-query-execution-malformed-sql-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-query-execution-malformed-sql-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution rejects malformed SQL synchronously with InvalidRequestException and the
    parser message, minting no QueryExecutionId; valid SQL is accepted and visible via
    GetQueryExecution."""
    from botocore.exceptions import ClientError

    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"

    # A workgroup of the check's own scopes the execution listing to the calls made here.
    wg = ctx.unique_name("sim2real-behav-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    code = None
    message = None
    try:
        athena.start_query_execution(
            QueryString="SELEC 1 FRM dual !!!",
            WorkGroup=wg,
        )
        raise AssertionError("expected StartQueryExecution to reject malformed SQL, but it accepted it")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = (
        "line 1:1: mismatched input 'SELEC'. Expecting: 'ALTER', 'ANALYZE', 'CALL', 'COMMENT', "
        "'COMMIT', 'CREATE', 'DEALLOCATE', 'DELETE', 'DENY', 'DESC', 'DESCRIBE', 'DROP', 'EXECUTE', "
        "'EXPLAIN', 'GRANT', 'INSERT', 'MERGE', 'PREPARE', 'REFRESH', 'RESET', 'REVOKE', 'ROLLBACK', "
        "'SET', 'SHOW', 'START', 'TRUNCATE', 'UNLOAD', 'UPDATE', 'USE', <query>"
    )
    assert message == expected_message, f"expected parser message {expected_message!r}, got {message!r}"

    minted = athena.list_query_executions(WorkGroup=wg).get("QueryExecutionIds", [])
    assert not minted, f"malformed SQL must mint no QueryExecutionId, but found {minted}"

    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg)["QueryExecutionId"]
    assert qid, "expected StartQueryExecution to return a QueryExecutionId for valid SQL"
    deadline = time.monotonic() + 30.0
    while True:
        listed = athena.list_query_executions(WorkGroup=wg).get("QueryExecutionIds", [])
        if listed or time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    assert listed == [qid], f"expected the workgroup to list only the valid query {qid}, got {listed}"
    qe = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert qe["Status"]["State"] != "FAILED", f"expected the valid query to be accepted, got {qe['Status']}"


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "start-query-execution-malformed-sql-rejected"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
