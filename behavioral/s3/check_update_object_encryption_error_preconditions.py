"""update-object-encryption-error-preconditions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-object-encryption-error-preconditions"
GROUP = "error-semantics"
SERVICES = ["s3"]

MSG_NO_SUCH_KEY = "The specified key does not exist."
MSG_INVALID_KMS_ARN = (
    "Requests modifying object encryption configuration to SSE-KMS require a valid target kms "
    "key arn: Malformed ARN - doesn't start with 'arn:'"
)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateObjectEncryption returns NoSuchKey for a missing object, InvalidRequest for a malformed
    KMS key ARN, and AccessDenied under a key-policy deny, leaving the object untouched; lifting
    the deny or using an allowed key re-encrypts to SSE-KMS with bytes and ETag preserved."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]

    bucket = ctx.unique_name("sim2real-behav-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key = "encrypted-object.bin"
    body = b"needs-encryption-update" * 4
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    initial_head = s3.head_object(Bucket=bucket, Key=key)
    assert initial_head.get("ServerSideEncryption") in (None, "AES256"), (
        f"expected the freshly-put object to default to SSE-S3 (None or AES256), "
        f"got {initial_head.get('ServerSideEncryption')!r}"
    )

    plausible_arn = f"arn:aws:kms:{ctx.region}:{account_id}:key/00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket, Key="does-not-exist.bin", ObjectEncryption={"SSEKMS": {"KMSKeyArn": plausible_arn}}
        )
    )
    assert code == "NoSuchKey", f"expected NoSuchKey, got {code!r}"
    assert message == MSG_NO_SUCH_KEY, (
        f"expected the NoSuchKey message {MSG_NO_SUCH_KEY!r}, got {message!r}"
    )

    # The value must clear botocore's 20-char KMSKeyArn minimum so the server, not the client,
    # rejects it.
    code, message = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket, Key=key, ObjectEncryption={"SSEKMS": {"KMSKeyArn": "not-a-valid-kms-key-arn-string"}}
        )
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}"
    assert message == MSG_INVALID_KMS_ARN, (
        f"expected the InvalidRequest message {MSG_INVALID_KMS_ARN!r}, got {message!r}"
    )
    unchanged = s3.head_object(Bucket=bucket, Key=key)
    assert unchanged.get("ServerSideEncryption") in (None, "AES256"), (
        f"a rejected UpdateObjectEncryption must leave the object's encryption untouched: "
        f"expected None or AES256, got {unchanged.get('ServerSideEncryption')!r}"
    )

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                # S3 may call a GenerateDataKey* sibling, or kms:Encrypt directly for small
                # objects, so both must be denied for the precondition to hold.
                "Sid": "DenyGenerateDataKeyAndEncryptForEveryone",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["kms:GenerateDataKey*", "kms:Encrypt"],
                "Resource": "*",
            },
        ],
    }
    denied_key_id = kms.create_key(
        Description="sim2real-behav locked-down key",
        Policy=json.dumps(deny_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "update-object-encryption-error-preconditions"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=denied_key_id, PendingWindowInDays=7))

    # KMS key policies are eventually consistent; wait until the deny is enforced.
    _wait_for_deny_effective(kms, denied_key_id)

    code, message = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket, Key=key, ObjectEncryption={"SSEKMS": {"KMSKeyArn": denied_key_id}}
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    # S3 encrypts this small object with a direct kms:Encrypt, so that is the action KMS names.
    expected_denial = (
        f"User: {identity['Arn']} is not authorized to perform: kms:Encrypt on resource: "
        f"{denied_key_id} with an explicit deny in a resource-based policy"
    )
    assert message == expected_denial, (
        f"expected the AccessDenied message {expected_denial!r}, got {message!r}"
    )
    still_sse_s3 = s3.head_object(Bucket=bucket, Key=key)
    assert still_sse_s3.get("ServerSideEncryption") in (None, "AES256"), (
        f"a denied UpdateObjectEncryption must leave the object as SSE-S3: "
        f"expected None or AES256, got {still_sse_s3.get('ServerSideEncryption')!r}"
    )
    assert "SSEKMSKeyId" not in still_sse_s3, (
        f"a denied UpdateObjectEncryption must not attach an SSEKMSKeyId; head_object returned "
        f"{still_sse_s3.get('SSEKMSKeyId')!r}"
    )

    # Lifting the deny on the same key isolates the AccessDenied to the policy itself.
    restored_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
        ],
    }
    kms.put_key_policy(KeyId=denied_key_id, PolicyName="default", Policy=json.dumps(restored_policy))
    _wait_for_deny_lifted(kms, denied_key_id)

    # KMS answering our own calls does not mean S3's view of the policy has caught up, so the
    # identical call is retried on AccessDenied within a bounded window.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            s3.update_object_encryption(
                Bucket=bucket, Key=key, ObjectEncryption={"SSEKMS": {"KMSKeyArn": denied_key_id}}
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    restored_head = s3.head_object(Bucket=bucket, Key=key)
    assert restored_head["ServerSideEncryption"] == "aws:kms", (
        f"removing the deny statement must let the identical call succeed: expected aws:kms, "
        f"got {restored_head.get('ServerSideEncryption')!r}"
    )
    assert restored_head["SSEKMSKeyId"] == denied_key_id, (
        f"expected the object encrypted with the now-unblocked key {denied_key_id!r}, "
        f"got {restored_head.get('SSEKMSKeyId')!r}"
    )

    allowed_key_id = kms.create_key(
        Description="sim2real-behav allowed key",
        Tags=[{"TagKey": "sim2real", "TagValue": "update-object-encryption-error-preconditions"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=allowed_key_id, PendingWindowInDays=7))

    s3.update_object_encryption(Bucket=bucket, Key=key, ObjectEncryption={"SSEKMS": {"KMSKeyArn": allowed_key_id}})
    updated_head = s3.head_object(Bucket=bucket, Key=key)
    assert updated_head["ServerSideEncryption"] == "aws:kms", (
        f"expected a fully valid request to apply SSE-KMS, got "
        f"{updated_head.get('ServerSideEncryption')!r}"
    )
    assert updated_head["SSEKMSKeyId"] == allowed_key_id, (
        f"expected SSEKMSKeyId {allowed_key_id!r}, got {updated_head.get('SSEKMSKeyId')!r}"
    )
    # UpdateObjectEncryption re-encrypts without moving data: bytes and ETag are preserved.
    assert updated_head["ETag"] == initial_head["ETag"], (
        f"UpdateObjectEncryption must not move data: expected ETag {initial_head['ETag']!r}, "
        f"got {updated_head.get('ETag')!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == body, (
        "expected the object bytes to be unchanged after UpdateObjectEncryption"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the ClientError (code, message). An unexpected success raises, so
    accepting a call that AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_deny_effective(kms, key_id: str, timeout: float = 90.0, interval: float = 3.0) -> None:
    """Poll KMS until the Deny on key_id is enforced for both GenerateDataKey and Encrypt,
    bounding the documented KMS key-policy propagation delay."""
    deadline = time.monotonic() + timeout
    generate_data_key_denied = False
    encrypt_denied = False
    while True:
        if not generate_data_key_denied:
            try:
                kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
            except ClientError as exc:
                if exc.response["Error"]["Code"] in ("AccessDeniedException", "AccessDenied"):
                    generate_data_key_denied = True
                else:
                    raise
        if not encrypt_denied:
            try:
                kms.encrypt(KeyId=key_id, Plaintext=b"probe-bytes")
            except ClientError as exc:
                if exc.response["Error"]["Code"] in ("AccessDeniedException", "AccessDenied"):
                    encrypt_denied = True
                else:
                    raise
        if generate_data_key_denied and encrypt_denied:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"KMS deny policy on {key_id!r} did not take effect within {timeout}s "
                f"(generate_data_key_denied={generate_data_key_denied}, encrypt_denied={encrypt_denied})"
            )
        time.sleep(interval)


def _wait_for_deny_lifted(kms, key_id: str, timeout: float = 90.0, interval: float = 3.0) -> None:
    """Poll KMS until the restored policy on key_id permits both GenerateDataKey and Encrypt."""
    deadline = time.monotonic() + timeout
    generate_data_key_allowed = False
    encrypt_allowed = False
    while True:
        if not generate_data_key_allowed:
            try:
                kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
                generate_data_key_allowed = True
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("AccessDeniedException", "AccessDenied"):
                    raise
        if not encrypt_allowed:
            try:
                kms.encrypt(KeyId=key_id, Plaintext=b"probe-bytes")
                encrypt_allowed = True
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("AccessDeniedException", "AccessDenied"):
                    raise
        if generate_data_key_allowed and encrypt_allowed:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"KMS policy restore on {key_id!r} did not lift the deny within {timeout}s "
                f"(generate_data_key_allowed={generate_data_key_allowed}, encrypt_allowed={encrypt_allowed})"
            )
        time.sleep(interval)


def _create_bucket(s3, bucket: str, region: str) -> None:
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=bucket)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
