"""op-contract-getQueryExecution."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getQueryExecution"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryExecution reflects the real Query text, StatementType, WorkGroup and
    terminal Status.State/OutputLocation of a completed query; a malformed
    QueryExecutionId raises InvalidRequestException."""
    output_location = _create_output_bucket(ctx)
    wg = _create_workgroup(ctx, output_location)
    athena = ctx.client("athena")

    query = "SELECT 1 AS col"
    qid, state, exec_detail = _run_query_and_wait(ctx, query, wg)
    assert state == "SUCCEEDED", f"expected SUCCEEDED, got {state}"

    got = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert got["Query"] == query, f"expected Query {query!r}, got {got['Query']!r}"
    assert got["StatementType"] == "DML", f"expected StatementType DML, got {got['StatementType']!r}"
    assert got["WorkGroup"] == wg, f"expected WorkGroup {wg!r}, got {got['WorkGroup']!r}"
    assert got["Status"]["State"] == "SUCCEEDED", f"expected Status.State SUCCEEDED, got {got['Status']['State']!r}"
    assert got["ResultConfiguration"]["OutputLocation"].startswith(output_location), (
        f"expected OutputLocation to start with {output_location!r}, "
        f"got {got['ResultConfiguration']['OutputLocation']!r}"
    )

    code, message = _error(lambda: athena.get_query_execution(QueryExecutionId="not-a-real-id"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "QueryExecution not-a-real-id was not found", (
        f"expected 'QueryExecution not-a-real-id was not found', got {message!r}"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower()
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other
    # region requires it. Not a region pin on the check itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "get-query-execution-contract"},
    ]})

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
        Tags=[{"Key": "sim2real", "Value": "get-query-execution-contract"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    return wg


def _run_query_and_wait(ctx, query: str, workgroup: str, timeout_s: float = 120.0):
    athena = ctx.client("athena")
    qid = athena.start_query_execution(QueryString=query, WorkGroup=workgroup)["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    resp = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, resp
        time.sleep(1.5)
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
