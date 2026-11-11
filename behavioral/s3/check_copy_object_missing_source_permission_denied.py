"""copy-object-missing-source-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-missing-source-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3"]

_HEAD_ABSENT = ("404", 'Not Found')
_NO_POLICY = ("NoSuchBucketPolicy", 'The bucket policy does not exist')


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject from a source object explicitly denied s3:GetObject is rejected, not silently permitted."""
    s3 = ctx.client("s3")
    src_bucket = ctx.unique_name("sim2real-cp-src-")
    dst_bucket = ctx.unique_name("sim2real-cp-dst-")

    s3.create_bucket(Bucket=src_bucket, **_bucket_location_kwargs(s3))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, src_bucket))
    s3.create_bucket(Bucket=dst_bucket, **_bucket_location_kwargs(s3))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, dst_bucket))

    denied_key = "denied-object.txt"
    allowed_key = "allowed-object.txt"
    s3.put_object(Bucket=src_bucket, Key=denied_key, Body=b"secret-payload")
    s3.put_object(Bucket=src_bucket, Key=allowed_key, Body=b"public-payload")

    # Explicit Deny on a bucket policy overrides even the bucket owner's own implicit
    # allow -- this is how we remove s3:GetObject on exactly one source object without
    # needing a second IAM principal.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyGetOnSpecificObject",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{src_bucket}/{denied_key}",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=src_bucket, Policy=json.dumps(policy))

    dest_key = "copied-denied.txt"
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    denied = _poll_for_error(
        lambda: s3.copy_object(
            Bucket=dst_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": denied_key},
        ),
        expected_code="AccessDenied",
        timeout_s=20.0,
    )
    want_denied = (
        "AccessDenied",
        f"User: {caller} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{src_bucket}/{denied_key}" with an explicit deny in a resource-based policy',
    )
    assert denied == want_denied, f"expected {want_denied!r}, got {denied!r}"

    # effect absent: the destination object was never created
    absent = _error(lambda: s3.head_object(Bucket=dst_bucket, Key=dest_key))
    assert absent == _HEAD_ABSENT, f"expected destination object absent {_HEAD_ABSENT!r}, got {absent!r}"

    # restore: removing the deny must let the IDENTICAL call now succeed -- proves the earlier
    # AccessDenied was caused by the policy, not by something else wrong with the request.
    s3.delete_bucket_policy(Bucket=src_bucket)
    gone = _error(lambda: s3.get_bucket_policy(Bucket=src_bucket))
    assert gone == _NO_POLICY, f"expected policy gone immediately {_NO_POLICY!r}, got {gone!r}"

    # The policy STORE updates immediately (proven above), but S3's authorization cache for the
    # explicit Deny it just enforced drains on its own timeline, independent of the store -- and
    # repeatedly re-issuing the SAME denied CopyObject while it drains was measured to extend how
    # long the negative decision stays cached rather than shorten it. So the drain is waited out on
    # an unrelated, harmless read (get_bucket_policy) that never touches the denied path, and only
    # then is the identical call retried.
    for _ in range(6):
        time.sleep(5.0)
        recheck = _error(lambda: s3.get_bucket_policy(Bucket=src_bucket))
        assert recheck == _NO_POLICY, f"policy reappeared: {recheck!r}"
    _poll_until_success(
        lambda: s3.copy_object(
            Bucket=dst_bucket,
            Key=dest_key,
            CopySource={"Bucket": src_bucket, "Key": denied_key},
        ),
        timeout_s=30.0,
        interval_s=10.0,
    )
    restored_head = s3.head_object(Bucket=dst_bucket, Key=dest_key)
    assert restored_head["ContentLength"] == len(b"secret-payload"), (
        f"expected the restored copy to carry the source object's bytes "
        f"({len(b'secret-payload')}), got {restored_head['ContentLength']}"
    )

    # positive control: copying the object that was never denied succeeds in the same bucket pair
    control_key = "copied-allowed.txt"
    s3.copy_object(
        Bucket=dst_bucket,
        Key=control_key,
        CopySource={"Bucket": src_bucket, "Key": allowed_key},
    )
    head = s3.head_object(Bucket=dst_bucket, Key=control_key)
    assert head["ContentLength"] == len(b"public-payload")


def _bucket_location_kwargs(s3):
    region = s3.meta.region_name
    if region and region != "us-east-1":
        return {"CreateBucketConfiguration": {"LocationConstraint": region}}
    return {}


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_for_error(fn, expected_code: str, timeout_s: float = 20.0, interval_s: float = 2.0):
    """Retry fn() until it raises ``expected_code`` (a freshly written policy propagates);
    return that refusal's (code, message). Still not refused at the deadline fails the check."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            if last[0] == expected_code:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected_code} within {timeout_s}s, last outcome: {last!r}")


def _poll_until_success(fn, timeout_s: float = 20.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"expected success within {timeout_s}s, last error: {last_exc}")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
