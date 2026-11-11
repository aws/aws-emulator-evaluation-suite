"""put-object-invalid-write-offset-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-invalid-write-offset-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]

# S3 Express One Zone is only enabled in one specific Availability Zone per region (a fixed
# AWS platform fact, not an account-adjustable quota); any other AZ makes CreateBucket reject the
# directory-bucket name outright with InvalidBucketName rather than a capability-not-supported error.
EXPRESS_ZONE_IDS = {
    "us-east-1": "use1-az4",
    "us-east-2": "use2-az1",
    "us-west-2": "usw2-az1",
    "ap-south-1": "aps1-az1",
    "ap-northeast-1": "apne1-az1",
    "eu-central-1": "euc1-az1",
    "eu-west-1": "euw1-az1",
    "eu-north-1": "eun1-az1",
}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject append with an out-of-order x-amz-write-offset-bytes on a directory-bucket
    appendable object returns InvalidWriteOffset and leaves the object unmodified; a
    correctly-offset append succeeds and the bytes are appended in order."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket(ctx)

    key = ctx.unique_name("append-obj") + ".log"
    initial_body = b"0123456789"  # 10 bytes

    try:
        s3.put_object(Bucket=bucket, Key=key, Body=initial_body)
    except ClientError as exc:
        raise AssertionError(f"unreachable: directory bucket PutObject unsupported here ({exc})") from exc

    # Positive control: append at the correct current object size succeeds.
    good_chunk = b"ABCDE"
    s3.put_object(Bucket=bucket, Key=key, Body=good_chunk, WriteOffsetBytes=len(initial_body))
    grown = s3.head_object(Bucket=bucket, Key=key)
    expected_grown_size = len(initial_body) + len(good_chunk)
    assert grown["ContentLength"] == expected_grown_size, (
        f"expected ContentLength {expected_grown_size} after a correctly-offset append, got {grown['ContentLength']}"
    )
    body_after_good_append = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body_after_good_append == initial_body + good_chunk, (
        f"expected the append to be placed at offset {len(initial_body)}, "
        f"got body {body_after_good_append!r}"
    )

    # Negative: append with a bogus (too-small) offset must be rejected as InvalidWriteOffset.
    current_size = len(initial_body) + len(good_chunk)
    bad_offset = current_size - 1  # does not match the object's actual current size
    code = _error_code(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"WRONG", WriteOffsetBytes=bad_offset)
    )
    assert code == ("InvalidWriteOffset", "The write offset value that you specified does not match the current object size."), f"expected InvalidWriteOffset, got {code!r}"

    # The rejected append must not have mutated the object.
    unchanged = s3.head_object(Bucket=bucket, Key=key)
    assert unchanged["ContentLength"] == current_size, (
        f"rejected append with bad offset {bad_offset} must not mutate the object: "
        f"expected ContentLength {current_size}, got {unchanged['ContentLength']}"
    )
    unchanged_body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert unchanged_body == initial_body + good_chunk, (
        f"rejected append with bad offset {bad_offset} must not mutate the object body, "
        f"got {unchanged_body!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_directory_bucket(ctx: Any) -> str:
    """Create an S3 Express One Zone directory bucket in this region's Express-enabled AZ."""
    s3 = ctx.client("s3")
    zone_id = EXPRESS_ZONE_IDS.get(ctx.region)
    if not zone_id:
        raise AssertionError(f"unreachable: no known S3 Express One Zone Availability Zone for region {ctx.region!r}")

    base = ctx.unique_name("s3xb").replace("_", "-").lower()
    bucket = f"{base}--{zone_id}--x-s3"
    try:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
            },
        )
    except ClientError as exc:
        raise AssertionError(f"unreachable: S3 Express One Zone unavailable in this account/region ({exc})") from exc

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
