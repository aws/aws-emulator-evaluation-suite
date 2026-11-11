"""stop-query-execution-cancels-and-blocks-results."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-query-execution-cancels-and-blocks-results"
GROUP = 'query-execution'
SERVICES = ['athena']


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _empty_and_delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return f"s3://{bucket}/"


def _wait_for_query_terminal(athena, query_execution_id, timeout_s=60, interval_s=1.0):
    """Poll GetQueryExecution until the run reaches a terminal state; returns that state."""
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=query_execution_id)[
            "QueryExecution"
        ]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {query_execution_id} did not reach a terminal state within {timeout_s}s (last={state})"
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQueryExecution drives a run to CANCELLED, after which GetQueryResults rejects the request,
    while a query left to finish returns its results."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-cancel-")
    output_loc = _output_location(ctx)
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": output_loc}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    control_qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg)["QueryExecutionId"]
    control_state = _wait_for_query_terminal(athena, control_qid, timeout_s=60)
    assert control_state == "SUCCEEDED", f"positive control query did not succeed, got {control_state}"
    control_rows = athena.get_query_results(QueryExecutionId=control_qid)["ResultSet"]["Rows"]
    assert control_rows[1]["Data"][0]["VarCharValue"] == "1", (
        f"positive control results must be readable, got {control_rows}"
    )

    # A heavy in-memory computation gives StopQueryExecution a real window to land
    # before the query would otherwise reach SUCCEEDED.
    heavy_query = "SELECT count(*) FROM UNNEST(SEQUENCE(0, 20000000)) AS t(x)"
    resp = athena.start_query_execution(QueryString=heavy_query, WorkGroup=wg)
    qid = resp["QueryExecutionId"]
    # Registered so a mid-check failure still stops a query that is still running.
    ctx.on_cleanup(lambda: athena.stop_query_execution(QueryExecutionId=qid))

    athena.stop_query_execution(QueryExecutionId=qid)

    final_state = _wait_for_query_terminal(athena, qid, timeout_s=90)

    if final_state != "CANCELLED":
        raise AssertionError(
            f"query reached terminal state {final_state!r} before it could be cancelled"
        )

    err = _error(lambda: athena.get_query_results(QueryExecutionId=qid))
    expected = ("InvalidRequestException", "Could not find results")
    assert err == expected, f"expected {expected} fetching results of a cancelled query, got {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
