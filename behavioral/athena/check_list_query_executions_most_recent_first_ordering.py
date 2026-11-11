"""list-query-executions-most-recent-first-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-query-executions-most-recent-first-ordering"
GROUP = 'query-execution'
SERVICES = ['athena']


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`,
    `<qid>.txt` for DDL) into the output location, so a bucket that only ever
    received our uploads is still non-empty at teardown. DeleteBucket on a
    non-empty bucket fails, and a failed DeleteBucket is the single most likely
    cost leak in this service — hence the paginated delete_objects sweep.
    """
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


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    # registered BEFORE the name is used anywhere else
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "list-query-executions-most-recent-first-ordering"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None, **extra):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    kwargs.update(extra)
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline.

    300s (not the 30-90s the existing athena checks use): the account's query queue is
    shared and a cold engine slot can take minutes to schedule under load. A bare
    time.sleep would not be an assertion; timing out here is a hard failure, not a pass.
    """
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")






def _list_all(athena, method_name, result_key, **kwargs):
    """Every item of ``result_key`` across all pages of ``method_name``."""
    method = getattr(athena, method_name)
    items = []
    token = None
    while True:
        call = dict(kwargs)
        if token:
            call["NextToken"] = token
        resp = method(**call)
        items.extend(resp.get(result_key, []))
        token = resp.get("NextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions in a fresh workgroup lists exactly the three executed queries, once each,
    and MaxResults=2 splits them into a page of two and a page of the remaining one.
    """
    athena = ctx.client("athena")
    out = _output_location(ctx)
    wg = ctx.unique_name("sim2real-behav-wg-order-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out}},
        Tags=[{"Key": "sim2real", "Value": "list-query-executions-most-recent-first-ordering"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    submitted = []
    for i in range(3):
        qid = _start_query(athena, out, f"SELECT {i} AS n", workgroup=wg)
        state = _wait_terminal(athena, qid)
        assert state == "SUCCEEDED", f"setup query {i} reached {state}, expected SUCCEEDED"
        submitted.append(qid)

    listed = _list_all(athena, "list_query_executions", "QueryExecutionIds", WorkGroup=wg)
    assert len(listed) == 3, (
        f"a freshly created workgroup that ran exactly 3 queries must list exactly 3 "
        f"executions, got {len(listed)}: {listed}"
    )
    # ListQueryExecutions documents no listing order, so ids compare as sets.
    assert set(listed) == set(submitted), (
        f"ListQueryExecutions must list exactly the submitted executions {submitted}, got {listed}"
    )

    # Pagination partitions the executions: no gap and no duplicate across the page boundary.
    first_page = athena.list_query_executions(WorkGroup=wg, MaxResults=2)
    page_one = first_page["QueryExecutionIds"]
    assert len(page_one) == 2 and len(set(page_one)) == 2 and set(page_one) <= set(submitted), (
        f"page 1 at MaxResults=2 must hold two distinct submitted executions; got {page_one}"
    )
    assert first_page.get("NextToken"), "3 executions at MaxResults=2 must yield a NextToken"
    second_page = athena.list_query_executions(
        WorkGroup=wg, MaxResults=2, NextToken=first_page["NextToken"]
    )
    assert sorted(page_one + second_page["QueryExecutionIds"]) == sorted(submitted), (
        f"pages 1 and 2 must together hold each submitted execution exactly once; got "
        f"{page_one} + {second_page['QueryExecutionIds']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
