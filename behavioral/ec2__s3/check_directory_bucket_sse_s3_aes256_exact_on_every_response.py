"""directory-bucket-sse-s3-aes256-exact-on-every-response."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "directory-bucket-sse-s3-aes256-exact-on-every-response"
GROUP = "server_side_encryption"
SERVICES = ["ec2", "s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A directory bucket's default SSE-S3 encryption reports exactly 'AES256' on CreateSession,
    PutObject, HeadObject, GetObject and CopyObject, never an absent encryption field."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket(ctx)

    session = s3.create_session(Bucket=bucket)
    assert session.get("ServerSideEncryption") == "AES256", (
        f"CreateSession reported ServerSideEncryption {session.get('ServerSideEncryption')!r}, "
        "expected 'AES256'"
    )

    key = "sse-s3-put.bin"
    body = b"directory-bucket-sse-s3-exact"
    put = s3.put_object(Bucket=bucket, Key=key, Body=body)
    assert put.get("ServerSideEncryption") == "AES256", (
        f"PutObject reported ServerSideEncryption {put.get('ServerSideEncryption')!r}, "
        "expected 'AES256'"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("ServerSideEncryption") == "AES256", (
        f"HeadObject reported ServerSideEncryption {head.get('ServerSideEncryption')!r}, "
        "expected 'AES256'"
    )

    got = s3.get_object(Bucket=bucket, Key=key)
    assert got.get("ServerSideEncryption") == "AES256", (
        f"GetObject reported ServerSideEncryption {got.get('ServerSideEncryption')!r}, "
        "expected 'AES256'"
    )
    read_body = got["Body"].read()
    assert read_body == body, (
        f"GetObject returned {read_body!r}, expected the {body!r} that was written"
    )

    copy_key = "sse-s3-copy.bin"
    copy = s3.copy_object(Bucket=bucket, Key=copy_key, CopySource={"Bucket": bucket, "Key": key})
    assert copy.get("ServerSideEncryption") == "AES256", (
        f"CopyObject reported ServerSideEncryption {copy.get('ServerSideEncryption')!r}, "
        "expected 'AES256'"
    )

    head_copy = s3.head_object(Bucket=bucket, Key=copy_key)
    assert head_copy.get("ServerSideEncryption") == "AES256", (
        f"HeadObject on the copy reported ServerSideEncryption "
        f"{head_copy.get('ServerSideEncryption')!r}, expected 'AES256'"
    )


def _create_directory_bucket(ctx: Any) -> str:
    """Create an S3 Express One Zone directory bucket, trying each available AZ id in turn.
    S3 Express is not offered in every AZ, so one AZ id can refuse with InvalidBucketName while a
    sibling accepts; only a refusal from all of them is treated as unreachable."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    try:
        azs = ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    except ClientError as exc:
        raise AssertionError(f"unreachable: cannot resolve Availability Zones ({exc})") from exc
    zone_ids = [az["ZoneId"] for az in azs if az.get("ZoneId")]
    assert zone_ids, "unreachable: no available Availability Zone ids to place a directory bucket"

    base = ctx.unique_name("s3xb").replace("_", "-").lower()
    bucket = None
    refusals: dict[str, str | None] = {}
    for zone_id in zone_ids:
        candidate = f"{base}--{zone_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=candidate,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            refusals[zone_id] = exc.response.get("Error", {}).get("Code")
            continue
        bucket = candidate
        break
    assert bucket is not None, (
        f"unreachable: no Availability Zone accepted an S3 Express directory bucket; "
        f"refusals were {refusals!r} over zones {zone_ids!r}"
    )

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
