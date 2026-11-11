"""put-object-append-write-offset-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "put-object-append-write-offset-rejected"
GROUP = 'directory_buckets'
SERVICES = ['s3']

# S3 Express One Zone requires pinning the bucket to one specific Availability Zone ID at
# creation; there is no region-relative way to ask for "an AZ in ctx.region", so each region
# needs its own literal AZ ID (fixed per-region resource, not an account/quota value).
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


def _delete_directory_bucket(client, bucket):
    """Delete every object + abort lingering multipart uploads in a directory bucket, then delete it."""
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []) or []:
                try:
                    client.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        resp = client.list_multipart_uploads(Bucket=bucket)
        for u in resp.get("Uploads", []) or []:
            try:
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "NoSuchBucket",
                    "NoSuchKey",
                    "NoSuchUpload",
                ):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_directory_bucket(ctx, s3):
    """Create an S3 Express One Zone directory bucket (non-ctx Zonal capability), register teardown."""
    zone_id = EXPRESS_ZONE_IDS.get(ctx.region)
    if not zone_id:
        raise AssertionError(f"no known S3 Express One Zone Availability Zone for region {ctx.region!r}")
    name = f"{ctx.unique_name('sim2real-dir-')}--{zone_id}--x-s3"
    try:
        s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                "Bucket": {"Type": "Directory", "DataRedundancy": "SingleAvailabilityZone"},
            },
        )
    except Exception as exc:
        raise AssertionError(f"directory bucket creation not supported here: {exc}") from exc
    ctx.on_cleanup(lambda: _delete_directory_bucket(s3, name))
    return name


def _err_code(fn):
    """Call fn(); return its botocore (code, message) if a ClientError is raised. An unexpected
    SUCCESS raises rather than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On an S3 Express One Zone directory bucket, an append PutObject whose WriteOffsetBytes differs
    from the object size is rejected with InvalidWriteOffset and its exact message and leaves the
    content unchanged, while a correct-offset append grows it."""
    s3 = ctx.client("s3")
    bucket = _new_directory_bucket(ctx, s3)
    key = "wo-target.bin"
    initial = b"123456789"  # 9 bytes
    s3.put_object(Bucket=bucket, Key=key, Body=initial)

    # Positive control: appending at the CORRECT current offset must succeed and the bytes must
    # actually land in order. Without this, a target that rejects every WriteOffsetBytes append
    # (i.e. never implements append at all) would pass this check just as well as one that
    # implements append and correctly validates the offset.
    good_tail = b"ABCDE"
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=good_tail, WriteOffsetBytes=len(initial))
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks WriteOffsetBytes support: {exc}") from exc
    grown = initial + good_tail
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == grown, (
        "a correctly-offset append must land its bytes in order"
    )

    # Negative: an append whose WriteOffsetBytes does NOT equal the object's current size (now
    # len(grown)) must be rejected with InvalidWriteOffset, and must not mutate the object.
    bad_offset = len(grown) + 999
    code = _err_code(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"tail-bytes", WriteOffsetBytes=bad_offset)
    )
    assert code == ("InvalidWriteOffset", "The write offset value that you specified does not match the current object size."), f"expected InvalidWriteOffset, got {code}"

    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == grown, (
        "object must be unmodified after a rejected append"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
