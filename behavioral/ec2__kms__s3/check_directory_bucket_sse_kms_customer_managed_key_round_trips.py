"""directory-bucket-sse-kms-customer-managed-key-round-trips."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "directory-bucket-sse-kms-customer-managed-key-round-trips"
GROUP = "server_side_encryption"
SERVICES = ["ec2", "kms", "s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A directory bucket's SSE-KMS default encryption with a customer managed key and
    BucketKeyEnabled encrypts PutObject and CopyObject; CreateSession and HeadObject
    report the same key, algorithm and bucket-key setting."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _create_directory_bucket(ctx)

    key = kms.create_key(
        Description="sim2real-behav s3 directory bucket sse-kms default encryption",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": key_arn,
                },
                "BucketKeyEnabled": True,
            }]
        },
    )
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    default = rules[0]["ApplyServerSideEncryptionByDefault"]
    assert default.get("SSEAlgorithm") == "aws:kms" and default.get("KMSMasterKeyID") == key_arn, (
        f"stored default encryption is {default!r}, expected aws:kms with key {key_arn!r}"
    )
    assert rules[0].get("BucketKeyEnabled") is True, (
        f"stored BucketKeyEnabled is {rules[0].get('BucketKeyEnabled')!r}, expected True"
    )

    session = s3.create_session(Bucket=bucket)
    _assert_sse_kms(session, key_arn, "CreateSession")

    put_key = "sse-kms-put.bin"
    body = b"directory-bucket-kms-put"
    put = s3.put_object(Bucket=bucket, Key=put_key, Body=body)
    _assert_sse_kms(put, key_arn, "PutObject")

    head_put = s3.head_object(Bucket=bucket, Key=put_key)
    _assert_sse_kms(head_put, key_arn, "HeadObject (PutObject target)")

    copy_key = "sse-kms-copy.bin"
    copy = s3.copy_object(Bucket=bucket, Key=copy_key, CopySource={"Bucket": bucket, "Key": put_key})
    assert copy.get("ServerSideEncryption") == "aws:kms", (
        f"CopyObject reported ServerSideEncryption {copy.get('ServerSideEncryption')!r}, "
        "expected 'aws:kms'"
    )
    assert copy.get("SSEKMSKeyId") == key_arn, (
        f"CopyObject reported SSEKMSKeyId {copy.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )
    # CopyObject's own response reports BucketKeyEnabled False even though the copied object
    # is stored with it True (confirmed by the HeadObject read below); that is what AWS returns.
    assert copy.get("BucketKeyEnabled") is False, (
        f"CopyObject reported BucketKeyEnabled {copy.get('BucketKeyEnabled')!r}, expected False"
    )

    head_copy = s3.head_object(Bucket=bucket, Key=copy_key)
    _assert_sse_kms(head_copy, key_arn, "HeadObject (CopyObject target)")


def _assert_sse_kms(resp: dict, key_arn: str, label: str) -> None:
    assert resp.get("ServerSideEncryption") == "aws:kms", (
        f"{label} reported ServerSideEncryption {resp.get('ServerSideEncryption')!r}, "
        "expected 'aws:kms'"
    )
    assert resp.get("SSEKMSKeyId") == key_arn, (
        f"{label} reported SSEKMSKeyId {resp.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )
    assert resp.get("BucketKeyEnabled") is True, (
        f"{label} reported BucketKeyEnabled {resp.get('BucketKeyEnabled')!r}, expected True"
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
