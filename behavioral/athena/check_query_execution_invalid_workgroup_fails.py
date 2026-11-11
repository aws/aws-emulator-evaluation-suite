"""query-execution-invalid-workgroup-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-invalid-workgroup-fails"
GROUP = 'overly-permissive'
SERVICES = ['athena']


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object before DeleteBucket: Athena writes its own result artifacts into the
    output location, so a bucket that only ever received our uploads is still non-empty at
    teardown."""
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
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-execution-invalid-workgroup"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return f"s3://{bucket}/results/"


def _wait_terminal(athena, qid, timeout_s=60, interval_s=2):
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution on a WorkGroup that does not exist fails with InvalidRequestException and
    never falls back to the default workgroup; on a real workgroup the same query reaches SUCCEEDED."""
    athena = ctx.client("athena")
    out = _output_location(ctx)

    wg = ctx.unique_name("sim2real-behav-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out}},
        Tags=[{"Key": "sim2real", "Value": "query-execution-invalid-workgroup"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    # --- the refusal: StartQueryExecution against a WorkGroup that does not exist ---
    bogus_wg = ctx.unique_name("sim2real-behav-wg-missing-")
    try:
        athena.start_query_execution(QueryString="SELECT 1", WorkGroup=bogus_wg)
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
    else:
        raise AssertionError(f"real AWS rejects StartQueryExecution against the nonexistent "
                             f"WorkGroup {bogus_wg!r}, but it SUCCEEDED")
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for nonexistent WorkGroup {bogus_wg!r}, got {code!r}")
    assert message == "WorkGroup is not found.", (
        f"unexpected nonexistent-WorkGroup refusal message: {message!r}")

    # --- the positive control: the identical call against a real workgroup succeeds ---
    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg)["QueryExecutionId"]
    state = _wait_terminal(athena, qid)
    assert state == "SUCCEEDED", (
        f"the identical StartQueryExecution against the real workgroup {wg!r} must succeed, "
        f"proving the refusal above was about the WorkGroup name and not a broken call; "
        f"got {state!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
