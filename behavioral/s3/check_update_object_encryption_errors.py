"""update-object-encryption-errors."""

from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "update-object-encryption-errors"
GROUP = 'server_side_encryption'
SERVICES = ['s3']

MSG_NO_SUCH_KEY = "The specified key does not exist."
MSG_INVALID_KMS_ARN = (
    "Requests modifying object encryption configuration to SSE-KMS require a valid target kms "
    "key arn: Malformed ARN - doesn't start with 'arn:'"
)
MSG_ACCESS_DENIED = "Access Denied"


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateObjectEncryption answers NoSuchKey for a missing object and InvalidRequest for a malformed KMS
    key ARN, refuses a mismatched ExpectedBucketOwner with AccessDenied even for the caller's own KMS key,
    and with the correct owner re-encrypts the object to aws:kms under that key."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]
    wrong_owner = "111122223333"

    bucket = _new_bucket(ctx, s3)
    key = "uoe-target.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"encrypt-me")  # SSE-S3 by default

    fake_kms_arn = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000"

    try:
        code1, msg1 = _err(
            lambda: s3.update_object_encryption(
                Bucket=bucket,
                Key="never-created.txt",
                ObjectEncryption={"SSEKMS": {"KMSKeyArn": fake_kms_arn}},
            )
        )
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks UpdateObjectEncryption support: {exc}") from exc
    assert code1 == "NoSuchKey", f"expected NoSuchKey, got {code1}"
    assert msg1 == MSG_NO_SUCH_KEY, (
        f"expected the NoSuchKey message {MSG_NO_SUCH_KEY!r}, got {msg1!r}"
    )

    code2, msg2 = _err(
        lambda: s3.update_object_encryption(
            Bucket=bucket,
            Key=key,
            ObjectEncryption={"SSEKMS": {"KMSKeyArn": "not-a-valid-kms-key-arn-format"}},
        )
    )
    assert code2 == "InvalidRequest", f"expected InvalidRequest, got {code2}"
    assert msg2 == MSG_INVALID_KMS_ARN, (
        f"expected the InvalidRequest message {MSG_INVALID_KMS_ARN!r}, got {msg2!r}"
    )
    after_code2 = s3.head_object(Bucket=bucket, Key=key)
    assert after_code2.get("ServerSideEncryption") in (None, "AES256"), (
        "a rejected malformed-KMS-ARN request must not change the object's encryption, got "
        f"{after_code2.get('ServerSideEncryption')!r}"
    )

    # A key the account owns and could otherwise use, so the AccessDenied below can only be
    # attributed to the ExpectedBucketOwner mismatch.
    own_key_arn = kms.create_key(
        Description="sim2real-behav uoe-owner-guard key",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=own_key_arn, PendingWindowInDays=7))

    code3, msg3 = _err(
        lambda: s3.update_object_encryption(
            Bucket=bucket,
            Key=key,
            ObjectEncryption={"SSEKMS": {"KMSKeyArn": own_key_arn}},
            ExpectedBucketOwner=wrong_owner,
        )
    )
    assert code3 == "AccessDenied", f"expected AccessDenied for a mismatched ExpectedBucketOwner, got {code3}"
    assert msg3 == MSG_ACCESS_DENIED, (
        f"expected the AccessDenied message {MSG_ACCESS_DENIED!r}, got {msg3!r}"
    )
    after_code3 = s3.head_object(Bucket=bucket, Key=key)
    assert after_code3.get("ServerSideEncryption") in (None, "AES256"), (
        "a mismatched ExpectedBucketOwner must not change the object's encryption, got "
        f"{after_code3.get('ServerSideEncryption')!r}"
    )

    # Positive control: the identical request with the correct owner succeeds and actually
    # re-encrypts the object, proving the AccessDenied above was caused by the owner mismatch
    # and not by the KMS key being unusable.
    s3.update_object_encryption(
        Bucket=bucket,
        Key=key,
        ObjectEncryption={"SSEKMS": {"KMSKeyArn": own_key_arn}},
        ExpectedBucketOwner=account,
    )
    updated = s3.head_object(Bucket=bucket, Key=key)
    assert updated.get("ServerSideEncryption") == "aws:kms", (
        f"expected the object to be re-encrypted to SSE-KMS, got {updated.get('ServerSideEncryption')!r}"
    )
    assert updated.get("SSEKMSKeyId") == own_key_arn, (
        f"expected the object's KMS key to be {own_key_arn!r}, got {updated.get('SSEKMSKeyId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
