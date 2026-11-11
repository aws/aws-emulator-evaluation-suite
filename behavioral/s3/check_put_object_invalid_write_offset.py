"""put-object-invalid-write-offset."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-invalid-write-offset"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject append-mode (S3 Express One Zone directory buckets) with a
    WriteOffsetBytes value that does not match the object's current length returns
    InvalidWriteOffset instead of silently appending at the wrong position."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket(ctx)
    key = "append-object.bin"
    initial = b"0123456789"

    s3.put_object(Bucket=bucket, Key=key, Body=initial)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == len(initial), (
        f"expected the initial object to be {len(initial)} bytes, got {head['ContentLength']!r}"
    )

    # Positive control: appending at the object's actual current length must succeed and the
    # bytes must land at the end, in order. Without this, "rejects a mismatched offset" is
    # indistinguishable from "rejects every WriteOffsetBytes append".
    good_chunk = b"ABCDE"
    s3.put_object(Bucket=bucket, Key=key, Body=good_chunk, WriteOffsetBytes=len(initial))
    grown = s3.head_object(Bucket=bucket, Key=key)
    assert grown["ContentLength"] == len(initial) + len(good_chunk), (
        f"a correctly-offset append should grow the object to {len(initial) + len(good_chunk)} "
        f"bytes, got {grown['ContentLength']!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == initial + good_chunk, (
        "a correctly-offset append must land its bytes at the end, in order"
    )

    current_size = len(initial) + len(good_chunk)
    wrong_offset = current_size + 999
    code = _error_code(
        lambda: s3.put_object(
            Bucket=bucket, Key=key, Body=b"tail-bytes", WriteOffsetBytes=wrong_offset
        )
    )
    assert code == ("InvalidWriteOffset", "The write offset value that you specified does not match the current object size."), (
        f"expected InvalidWriteOffset appending at a mismatched offset, got {code!r}"
    )

    # Object must be unchanged after the rejected append.
    head_after = s3.head_object(Bucket=bucket, Key=key)
    assert head_after["ContentLength"] == current_size, (
        f"rejected append must not mutate the object's length; expected {current_size}, "
        f"got {head_after['ContentLength']!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == initial + good_chunk, (
        "rejected append must not mutate the object's bytes"
    )

    # And a further legal append still works, so the rejection did not wedge the object.
    final_chunk = b"ZZ"
    s3.put_object(Bucket=bucket, Key=key, Body=final_chunk, WriteOffsetBytes=current_size)
    final = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final == initial + good_chunk + final_chunk, (
        f"a legal append after the rejection should produce {initial + good_chunk + final_chunk!r}, "
        f"got {final!r}"
    )


def _create_directory_bucket(ctx):
    """Create an S3 Express One Zone directory bucket.

    S3 Express One Zone is not offered in every AZ of a region (measured: the first AZ
    DescribeAvailabilityZones returns can answer InvalidBucketName while another AZ in the
    same region succeeds), so every available AZ is tried in turn rather than trusting the
    first one listed.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    try:
        azs = ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    except ClientError as exc:
        raise AssertionError(f"cannot list availability zones: {exc}") from exc
    if not azs:
        raise AssertionError("no availability zones available for an S3 Express directory bucket")

    base = ctx.unique_name("sim2real").rstrip("-").replace("-", "")[:20]
    refusals = {}
    for az in azs:
        az_id = az["ZoneId"]
        bucket = f"{base}--{az_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Name": az_id, "Type": "AvailabilityZone"},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            refusals[az_id] = exc.response.get("Error", {}).get("Code", str(exc))
            continue

        def _cleanup(bucket=bucket):
            try:
                resp = s3.list_objects_v2(Bucket=bucket)
                for obj in resp.get("Contents", []):
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

    raise AssertionError(
        f"S3 Express One Zone directory buckets not available in {ctx.region}: "
        f"no AZ accepted one; refusals were {refusals!r} over zones {[a['ZoneId'] for a in azs]!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
