"""query-execution-disabled-workgroup-rejects-start."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-disabled-workgroup-rejects-start"
GROUP = 'overly-permissive'
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
        # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-execution-disabled-workgroup-rejects-start"},
    ]})
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

def _workgroup_execution_ids(athena, wg):
    """QueryExecutionIds ListQueryExecutions reports for wg — an independent read through a
    different operation than StartQueryExecution/GetQueryExecution."""
    ids = []
    paginator = athena.get_paginator("list_query_executions")
    for page in paginator.paginate(WorkGroup=wg):
        ids.extend(page.get("QueryExecutionIds", []))
    return ids


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DISABLED WorkGroup must refuse StartQueryExecution, and accept again once re-ENABLED."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    wg = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out}},
        Tags=[{"Key": "sim2real", "Value": "query-execution-disabled-workgroup-rejects-start"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    # positive control: while ENABLED the workgroup admits and actually completes a query
    qid = _start_query(athena, out, "SELECT 1 AS col1", workgroup=wg)
    baseline_state = _wait_terminal(athena, qid, timeout_s=90)
    assert baseline_state == "SUCCEEDED", (
        f"baseline query against an ENABLED workgroup must SUCCEED before the gate is even "
        f"tested, got {baseline_state!r}"
    )

    athena.update_work_group(WorkGroup=wg, State="DISABLED")
    assert athena.get_work_group(WorkGroup=wg)["WorkGroup"]["State"] == "DISABLED", (
        "UpdateWorkGroup(State='DISABLED') did not take effect on GetWorkGroup"
    )

    try:
        _start_query(athena, out, "SELECT 1 AS col1", workgroup=wg)
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
    else:
        raise AssertionError("real AWS rejects StartQueryExecution on a DISABLED workgroup, "
                             "but it SUCCEEDED")
    assert code == "InvalidRequestException", (
        f"expected DISABLED workgroup to reject StartQueryExecution, got {code}"
    )
    assert message == f"WorkGroup {wg} is disabled.", (
        f"unexpected DISABLED-workgroup refusal message: {message!r}"
    )

    # effect absent: the rejected call admitted nothing — ListQueryExecutions (a different
    # operation than the one that mutated) still shows only the baseline execution
    after_reject_ids = _workgroup_execution_ids(athena, wg)
    assert after_reject_ids == [qid], (
        f"a StartQueryExecution rejected with InvalidRequestException must not admit a new "
        f"execution; ListQueryExecutions(WorkGroup={wg!r}) returned {after_reject_ids!r}, "
        f"expected only the baseline {[qid]!r}"
    )

    # re-enabling restores acceptance -> the gate is state-driven, not permanent
    athena.update_work_group(WorkGroup=wg, State="ENABLED")
    qid2 = _start_query(athena, out, "SELECT 1 AS col1", workgroup=wg)
    assert qid2 != qid, "re-enabled workgroup should start a genuinely new execution"
    restored_state = _wait_terminal(athena, qid2, timeout_s=90)
    assert restored_state == "SUCCEEDED", (
        f"the identical query refused a moment ago must SUCCEED once the workgroup is "
        f"re-ENABLED, proving the refusal was the DISABLED state and not a broken workgroup; "
        f"got {restored_state!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
