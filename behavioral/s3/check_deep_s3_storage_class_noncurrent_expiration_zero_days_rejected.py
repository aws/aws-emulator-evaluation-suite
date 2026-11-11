"""deep-s3-storage-class-noncurrent-expiration-zero-days-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-noncurrent-expiration-zero-days-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """NoncurrentVersionExpiration with NoncurrentDays=0 is refused InvalidArgument and leaves the
    versioned bucket with NoSuchLifecycleConfiguration, while the identical rule with
    NoncurrentDays=1 is stored and read back, pinning the refusal on the day value."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-nc-")

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def rule(days: int) -> list:
        return [{
            "ID": "noncurrent-expiry",
            "Status": "Enabled",
            "Filter": {"Prefix": "logs/"},
            "NoncurrentVersionExpiration": {"NoncurrentDays": days},
        }]

    code, message = _error_code(lambda: s3.put_bucket_lifecycle_configuration(
        Bucket=bucket, LifecycleConfiguration={"Rules": rule(0)},
    ))
    assert code == "InvalidArgument", f"NoncurrentDays=0 returned {code!r}, expected InvalidArgument"
    assert message == "'NoncurrentDays' for NoncurrentVersionExpiration action must be a positive integer", message

    absent, absent_message = _error_code(lambda: s3.get_bucket_lifecycle_configuration(Bucket=bucket))
    assert absent == "NoSuchLifecycleConfiguration", (
        f"after the refused PUT GetBucketLifecycleConfiguration returned {absent!r}, expected NoSuchLifecycleConfiguration"
    )
    assert absent_message == "The lifecycle configuration does not exist", absent_message

    # Positive control: identical rule, NoncurrentDays=1.
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": rule(1)})
    stored = _poll(ctx, lambda: _lifecycle_rules(s3, bucket), lambda got: isinstance(got, list))
    assert isinstance(stored, list) and len(stored) == 1, f"NoncurrentDays=1 rule read back as {stored!r}"
    nve = stored[0].get("NoncurrentVersionExpiration")
    assert nve == {"NoncurrentDays": 1}, f"stored NoncurrentVersionExpiration was {nve!r}"
    assert stored[0].get("Filter") == {"Prefix": "logs/"}, f"stored Filter was {stored[0].get('Filter')!r}"


def _lifecycle_rules(s3, bucket: str):
    """The bucket's lifecycle Rules, or the error code GetBucketLifecycleConfiguration returns."""
    try:
        return s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")


def _poll(ctx, fn, done, timeout_s: float = 60.0):
    """Call fn() every 2 s until done(result) or a 60 s deadline capped by ctx.time_left()."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        result = fn()
        if done(result) or time.monotonic() >= deadline:
            return result
        time.sleep(2)


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"])
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _error_code(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    over-permissive target is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
