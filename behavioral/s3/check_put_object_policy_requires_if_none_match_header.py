"""put-object-policy-requires-if-none-match-header."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-policy-requires-if-none-match-header"
GROUP = "conditional"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy denying PutObject whenever the if-none-match header is absent
    rejects a plain PutObject, and the identical write with If-None-Match: * succeeds."""
    s3 = ctx.client("s3")
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    bucket = _make_bucket(ctx, "sim2real-behav-putcond-")
    key = "object.txt"

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyPutWithoutIfNoneMatch",
            "Effect": "Deny",
            "Principal": {"AWS": ctx.account},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"Null": {"s3:if-none-match": "true"}},
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    want_denied = (
        "AccessDenied",
        f"User: {caller} is not authorized to perform: s3:PutObject on resource: "
        f'"arn:aws:s3:::{bucket}/{key}" with an explicit deny in a resource-based policy',
    )
    _await_policy(
        ctx,
        lambda n: s3.put_object(Bucket=bucket, Key=f"probe-{n}.txt", Body=b"probe"),
        expected_code="AccessDenied",
    )
    denied = _error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"plain-write"))
    assert denied == want_denied, f"expected {want_denied!r}, got {denied!r}"

    absent = _error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert absent[0] == "404", f"the denied write must leave no object, got {absent!r}"

    put = s3.put_object(Bucket=bucket, Key=key, Body=b"conditional-write", IfNoneMatch="*")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ETag"] == put["ETag"], (
        f"the conditional write must succeed and be readable back; "
        f"head ETag {head['ETag']!r} != put ETag {put['ETag']!r}"
    )


def _make_bucket(ctx, prefix: str) -> str:
    """A bucket under ctx.unique_name; cleanup removes the policy, then the bucket's contents."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; raises itself on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the run's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _await_policy(ctx, probe, expected_code: str, cap_s: float = 20.0, interval_s: float = 2.0):
    """Call probe(n) on a fresh throwaway key until it raises ``expected_code``, so a freshly
    written policy is in force before the asserted call; the asserted key is never retried."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    attempt = 0
    while True:
        attempt += 1
        try:
            result = probe(attempt)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            if last[0] == expected_code:
                return
        else:
            last = ("SUCCESS", result)
        if time.monotonic() + interval_s >= deadline:
            raise TimeoutError(
                f"expected {expected_code} within {timeout_s:.0f}s, last outcome: {last!r}"
            )
        time.sleep(interval_s)


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
