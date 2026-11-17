"""update-object-encryption-rekeys-sse-kms-object-to-a-different-customer-managed-key."""

from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-object-encryption-rekeys-sse-kms-object-to-a-different-customer-managed-key"
GROUP = "server-side-encryption"
SERVICES = ["s3", "kms"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateObjectEncryption re-keys an object already encrypted with one customer-managed KMS
    key to a different one, in place: the ETag, content and checksum are preserved across the
    key rotation."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _new_bucket(ctx, s3)
    key = "rekeyed-object.bin"
    body = b"rekey-across-customer-managed-keys" * 8

    key_arn_a = kms.create_key(
        Description="sim2real-behav update-object-encryption-rekeys-sse-kms-object-to-a-different-customer-managed-key-a"
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=key_arn_a, PendingWindowInDays=7), "NotFoundException",
    ))
    key_arn_b = kms.create_key(
        Description="sim2real-behav update-object-encryption-rekeys-sse-kms-object-to-a-different-customer-managed-key-b"
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=key_arn_b, PendingWindowInDays=7), "NotFoundException",
    ))

    put = s3.put_object(
        Bucket=bucket, Key=key, Body=body,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn_a,
        ChecksumAlgorithm="SHA256",
    )
    ctx.on_cleanup(_teardown(lambda: _delete_object(s3, bucket, key), "NoSuchKey"))

    before = s3.head_object(Bucket=bucket, Key=key)
    assert before.get("SSEKMSKeyId") == key_arn_a, (
        f"expected the object to start SSE-KMS encrypted with {key_arn_a!r}, got "
        f"{before.get('SSEKMSKeyId')!r}"
    )

    s3.update_object_encryption(
        Bucket=bucket, Key=key, ObjectEncryption={"SSEKMS": {"KMSKeyArn": key_arn_b}}
    )

    after = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert after.get("ServerSideEncryption") == "aws:kms", (
        f"expected the re-keyed object to stay SSE-KMS, got "
        f"{after.get('ServerSideEncryption')!r}"
    )
    assert after.get("SSEKMSKeyId") == key_arn_b, (
        f"expected the re-keyed object's SSEKMSKeyId to become {key_arn_b!r}, got "
        f"{after.get('SSEKMSKeyId')!r}"
    )
    assert after["ETag"] == before["ETag"], (
        f"UpdateObjectEncryption must preserve the object's ETag across a key rotation: expected "
        f"{before['ETag']!r}, got {after['ETag']!r}"
    )
    assert after["ChecksumSHA256"] == put["ChecksumSHA256"], (
        f"UpdateObjectEncryption must preserve the object's checksum across a key rotation: "
        f"expected {put['ChecksumSHA256']!r}, got {after.get('ChecksumSHA256')!r}"
    )

    read_back = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert read_back == body, (
        f"re-keying the object must not change its {len(body)}-byte content; read back "
        f"{len(read_back)} byte(s)"
    )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-uoerk-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _delete_object(s3, bucket: str, key: str, timeout_s: float = 60.0) -> None:
    """Delete the object, then read until it is gone, before its keys' teardown runs."""
    s3.delete_object(Bucket=bucket, Key=key)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.head_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{key!r} still readable {timeout_s:g} s after DeleteObject")
        time.sleep(2.0)


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
