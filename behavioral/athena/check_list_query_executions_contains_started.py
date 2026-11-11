"""list-query-executions-contains-started."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-query-executions-contains-started"
GROUP = 'query-execution'
SERVICES = ['athena']

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
    return f"s3://{bucket}/results/"

def _start_query(athena, out, query_string, workgroup=None, client_request_token=None, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if client_request_token:
        kwargs["ClientRequestToken"] = client_request_token
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]

def _wait_terminal(athena, qid, timeout_s=30, interval_s=1):
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")

@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions(WorkGroup=X) surfaces a query started in X and withholds a query
    started in a distinct workgroup Y, proving the listing is actually scoped rather than
    a flat, unfiltered account-wide view."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    wg = ctx.unique_name("sim2real-behav-wg-")
    wg_other = ctx.unique_name("sim2real-behav-wg-other-")
    for name in (wg, wg_other):
        athena.create_work_group(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda name=name: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    qid = _start_query(athena, out, "SELECT 1 AS col1", workgroup=wg)
    _wait_terminal(athena, qid, timeout_s=60)
    qid_other = _start_query(athena, out, "SELECT 2 AS col1", workgroup=wg_other)
    _wait_terminal(athena, qid_other, timeout_s=60)

    listed_in_wg = set(athena.list_query_executions(WorkGroup=wg)["QueryExecutionIds"])
    listed_in_other = set(athena.list_query_executions(WorkGroup=wg_other)["QueryExecutionIds"])

    assert qid in listed_in_wg, "started query execution not found in ListQueryExecutions(WorkGroup=wg)"
    assert qid_other in listed_in_other, (
        "control query execution not found in its own ListQueryExecutions(WorkGroup=wg_other)"
    )
    assert qid not in listed_in_other, (
        f"query {qid} started in {wg} leaked into ListQueryExecutions(WorkGroup={wg_other})"
    )
    assert qid_other not in listed_in_wg, (
        f"query {qid_other} started in {wg_other} leaked into ListQueryExecutions(WorkGroup={wg})"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
