"""update-object-encryption-error-paths."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-object-encryption-error-paths"
GROUP = "error-semantics"
SERVICES = ["s3"]

MSG_NO_SUCH_KEY = "The specified key does not exist."
MSG_ACCESS_DENIED = "The KMS key must be from the same account as the bucket"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateObjectEncryption returns NoSuchKey for a missing object and AccessDenied for both a
    malformed and a foreign-account KMS key ARN, leaving the object's key unchanged; a positive
    control on an owned key proves the operation can succeed."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _create_bucket(ctx)
    key = "encrypted-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    kms_key_arn = kms.create_key(Description="sim2real-behav update-object-encryption-error-paths")[
        "KeyMetadata"
    ]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=kms_key_arn, PendingWindowInDays=7))
    s3.update_object_encryption(Bucket=bucket, Key=key, ObjectEncryption={"SSEKMS": {"KMSKeyArn": kms_key_arn}})
    control_head = s3.head_object(Bucket=bucket, Key=key)
    assert control_head.get("ServerSideEncryption") == "aws:kms", (
        f"expected the positive control to switch the object to SSE-KMS, got "
        f"{control_head.get('ServerSideEncryption')!r}"
    )
    assert control_head.get("SSEKMSKeyId") == kms_key_arn, (
        f"expected SSEKMSKeyId {kms_key_arn!r} after the positive control, got "
        f"{control_head.get('SSEKMSKeyId')!r}"
    )

    foreign_arn = f"arn:aws:kms:{ctx.region}:111122223333:key/00000000-0000-0000-0000-000000000000"
    # ARN-shaped so it clears botocore's client-side KMSKeyArn validation and reaches S3.
    malformed_arn = f"arn:aws:kms:{ctx.region}:123456789012:key/not-a-valid-kms-key-identifier"

    code_missing, msg_missing = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket,
            Key="does-not-exist.bin",
            ObjectEncryption={"SSEKMS": {"KMSKeyArn": foreign_arn}},
        )
    )
    assert code_missing == "NoSuchKey", f"expected NoSuchKey for a missing object, got {code_missing!r}"
    assert msg_missing == MSG_NO_SUCH_KEY, (
        f"expected the NoSuchKey message {MSG_NO_SUCH_KEY!r}, got {msg_missing!r}"
    )

    # S3 does not reveal whether a key id is malformed or inaccessible: both are AccessDenied.
    code_malformed, msg_malformed = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket,
            Key=key,
            ObjectEncryption={"SSEKMS": {"KMSKeyArn": malformed_arn}},
        )
    )
    assert code_malformed == "AccessDenied", (
        f"expected AccessDenied for a malformed KMS key ARN, got {code_malformed!r}"
    )
    assert msg_malformed == MSG_ACCESS_DENIED, (
        f"expected the AccessDenied message {MSG_ACCESS_DENIED!r}, got {msg_malformed!r}"
    )
    after_malformed = s3.head_object(Bucket=bucket, Key=key)
    assert after_malformed.get("SSEKMSKeyId") == kms_key_arn, (
        f"a rejected UpdateObjectEncryption must not change the object's encryption, "
        f"expected SSEKMSKeyId {kms_key_arn!r}, got {after_malformed.get('SSEKMSKeyId')!r}"
    )

    # Customer-managed keys are restricted to the bucket owner's account by default.
    code_foreign, msg_foreign = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket,
            Key=key,
            ObjectEncryption={"SSEKMS": {"KMSKeyArn": foreign_arn}},
        )
    )
    assert code_foreign == "AccessDenied", (
        f"expected AccessDenied for a KMS key owned by a different account, got {code_foreign!r}"
    )
    assert msg_foreign == MSG_ACCESS_DENIED, (
        f"expected the AccessDenied message {MSG_ACCESS_DENIED!r}, got {msg_foreign!r}"
    )
    after_foreign = s3.head_object(Bucket=bucket, Key=key)
    assert after_foreign.get("SSEKMSKeyId") == kms_key_arn, (
        f"a rejected UpdateObjectEncryption must not change the object's encryption, "
        f"expected SSEKMSKeyId {kms_key_arn!r}, got {after_foreign.get('SSEKMSKeyId')!r}"
    )


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_object_versions(Bucket=name)
            for v in resp.get("Versions", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
            for m in resp.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=m["Key"], VersionId=m["VersionId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=name):
                for u in page.get("Uploads", []):
                    s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
