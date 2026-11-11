"""athena-s3-bucket-policy-blocks-query-results-write-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-s3-bucket-policy-blocks-query-results-write-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy denying s3:PutObject makes the Athena query end FAILED with no result object
    despite an identity policy that allows it; removing that Deny makes the same query succeed."""
    bucket = _create_bucket(ctx, "policydeny")

    s3 = ctx.client("s3")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyResultWrites",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(deny_policy))

    # Negative: query targets the bucket whose resource policy denies the write.
    prefix = "results/"
    query = "SELECT 'sim2real-bucket-policy' AS marker"
    output_location = f"s3://{bucket}/{prefix}"
    qid, state, exec_resp = _run_query(ctx, query=query, output_location=output_location)
    assert state == "FAILED", f"expected FAILED, got {state}: {exec_resp['Status']}"
    reason = exec_resp["Status"].get("StateChangeReason", "")
    assert "denied" in reason.lower() or "permission" in reason.lower(), reason
    _error_code(
        lambda: s3.head_object(Bucket=bucket, Key=f"{prefix}{qid}.csv"),
        expect="404",
        on_success=f"result object {prefix}{qid}.csv unexpectedly exists despite the denied write",
    )

    # Restore: remove only the Deny statement on the SAME bucket, then re-issue
    # the identical call -- proves the bucket, not some other bucket, was the cause.
    s3.delete_bucket_policy(Bucket=bucket)
    qid2, state2, exec_resp2 = _run_query(ctx, query=query, output_location=output_location)
    assert state2 == "SUCCEEDED", f"expected SUCCEEDED once the Deny was removed, got {state2}: {exec_resp2['Status']}"
    head = s3.head_object(Bucket=bucket, Key=f"{prefix}{qid2}.csv")
    assert head["ContentLength"] > 0, f"expected a non-empty result object at {prefix}{qid2}.csv, got ContentLength={head['ContentLength']}"


def _error_code(fn, *, expect: str, on_success: str):
    try:
        result = fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == expect, f"expected {expect}, got {code}"
        return code
    raise AssertionError(f"{on_success}; call unexpectedly succeeded with {result!r}")


def _create_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-athena-{kind}-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    # Bucket policy may itself deny PutObject/DeleteObject; clear it first so
    # cleanup does not get blocked by the very policy under test.
    try:
        s3.delete_bucket_policy(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _run_query(
    ctx,
    query: str,
    output_location: str,
    timeout_s: float = 120.0,
):
    athena = ctx.client("athena")
    resp = athena.start_query_execution(
        QueryString=query, ResultConfiguration={"OutputLocation": output_location}
    )
    qid = resp["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    exec_resp = None
    state = None
    while time.monotonic() < deadline:
        exec_resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = exec_resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, exec_resp
        time.sleep(2)
    raise AssertionError(f"query {qid} did not finish in {timeout_s}s, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
