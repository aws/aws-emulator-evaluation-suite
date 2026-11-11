"""put-object-encryption-type-mismatch-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-encryption-type-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Appending to a directory-bucket object with a different SSE type than its write session is
    rejected with InvalidRequest (not EncryptionTypeMismatch) and leaves the object unchanged;
    appends with the matching default encryption succeed before and after."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _create_directory_bucket(ctx)

    key = ctx.unique_name("append-enc") + ".log"
    initial_body = b"seed-data!"  # implicitly SSE-S3 encrypted (directory bucket default)

    try:
        created = s3.put_object(Bucket=bucket, Key=key, Body=initial_body)
    except ClientError as exc:
        raise AssertionError(f"unreachable: directory bucket PutObject unsupported here ({exc})") from exc
    assert created.get("ServerSideEncryption") in (None, "AES256"), (
        f"expected the default directory-bucket encryption (None or AES256), got "
        f"{created.get('ServerSideEncryption')!r}"
    )

    # Positive control: an append that doesn't change the SSE type succeeds.
    matching_chunk = b"-more"
    s3.put_object(Bucket=bucket, Key=key, Body=matching_chunk, WriteOffsetBytes=len(initial_body))
    size_after_good_append = len(initial_body) + len(matching_chunk)
    after_good_append = s3.head_object(Bucket=bucket, Key=key)
    assert after_good_append["ContentLength"] == size_after_good_append, (
        f"expected {size_after_good_append} bytes after the matching-encryption append, "
        f"got {after_good_append['ContentLength']!r}"
    )

    key_arn = kms.create_key(
        Description="sim2real-behav s3 append encryption mismatch test",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    # Negative: appending with a different SSE type (SSE-KMS) than the object's current
    # SSE-S3 encryption is rejected — as InvalidRequest, not EncryptionTypeMismatch. Real AWS
    # attributes the rejection to the write SESSION having been established with AES256, and
    # says so in the message; that message is asserted too, to separate this from any other
    # malformed-request InvalidRequest.
    code, message = _error_code(
        lambda: s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=b"-kms-chunk",
            WriteOffsetBytes=size_after_good_append,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=key_arn,
        )
    )
    assert (code, message) == ("InvalidRequest", "Session was created with ServerSideEncryption as AES256 but request header specifies SSE-KMS."), (
        f"expected the InvalidRequest message to name the session's committed encryption "
        f"and the mismatched SSE-KMS header, got {code!r} ({message!r})"
    )

    # The rejected append must not have mutated the object.
    still_unchanged = s3.head_object(Bucket=bucket, Key=key)
    assert still_unchanged["ContentLength"] == size_after_good_append, (
        f"the rejected mismatched-encryption append changed the object length: expected "
        f"{size_after_good_append}, got {still_unchanged['ContentLength']!r}"
    )
    assert still_unchanged.get("ServerSideEncryption") in (None, "AES256"), (
        f"the rejected mismatched-encryption append changed the object's encryption type to "
        f"{still_unchanged.get('ServerSideEncryption')!r}"
    )

    # Restore: retry the identical append with the object's actual (matching) encryption
    # type. It must now succeed, proving the earlier rejection was specific to the
    # encryption mismatch and did not wedge the object against further appends.
    restored_chunk = b"-restored"
    s3.put_object(Bucket=bucket, Key=key, Body=restored_chunk, WriteOffsetBytes=size_after_good_append)
    size_after_restore = size_after_good_append + len(restored_chunk)
    restored = s3.head_object(Bucket=bucket, Key=key)
    assert restored["ContentLength"] == size_after_restore, (
        f"expected {size_after_restore} bytes after the restored matching-encryption append, "
        f"got {restored['ContentLength']!r}"
    )



def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message).
    An unexpected success raises, so accepting refused input cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
