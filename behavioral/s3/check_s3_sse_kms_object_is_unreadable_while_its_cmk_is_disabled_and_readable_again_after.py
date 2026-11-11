"""s3-sse-kms-object-is-unreadable-while-its-cmk-is-disabled-and-readable-again-after."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-sse-kms-object-is-unreadable-while-its-cmk-is-disabled-and-readable-again-after"
GROUP = 'encryption-rejection'
SERVICES = ['s3']

_PAYLOAD = b"plaintext-that-only-a-real-kms-decrypt-can-give-back" * 16
_PROPAGATION_BUDGET_S = 120.0
_POLL_S = 3.0


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


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _retire_key(kms, key_id):
    """Re-enable then schedule deletion, so a mid-check failure never leaves a disabled key.

    7 days is the minimum PendingWindowInDays; a KMS key cannot be deleted immediately.
    """
    try:
        kms.enable_key(KeyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling an SSE-KMS object's CMK makes GetObject fail with KMS.DisabledException while
    HeadObject still succeeds, and re-enabling the key returns the exact original plaintext.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
    """
    s3 = ctx.client("s3")
    kms = ctx.client("kms")

    created = kms.create_key(
        Description=f"sim2real-behav sse-kms key-state check ({CHECK})",
        Tags=[{"TagKey": "sim2real", "TagValue": "s3-sse-kms-key-state"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    # Registered before any assertion: a key left disabled breaks later reads encrypted with it.
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    assert created["KeyState"] == "Enabled", (
        f"the new CMK is in state {created['KeyState']!r}, expected Enabled"
    )

    bucket = _new_bucket(ctx, s3)
    obj = "kms-encrypted.bin"
    put = s3.put_object(
        Bucket=bucket, Key=obj, Body=_PAYLOAD,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn,
    )
    assert put["ServerSideEncryption"] == "aws:kms", (
        f"PutObject reported ServerSideEncryption {put.get('ServerSideEncryption')!r}, want "
        "'aws:kms'"
    )
    assert put["SSEKMSKeyId"] == key_arn, (
        f"PutObject reported SSEKMSKeyId {put.get('SSEKMSKeyId')!r}, want {key_arn!r} — the object "
        "was not encrypted under the customer key that was asked for"
    )

    before = s3.get_object(Bucket=bucket, Key=obj)
    before_body = before["Body"].read()
    assert before_body == _PAYLOAD, (
        f"the encrypted object round-tripped to {len(before_body)} bytes, want {len(_PAYLOAD)}"
    )
    assert before["SSEKMSKeyId"] == key_arn, (
        f"GetObject reported SSEKMSKeyId {before.get('SSEKMSKeyId')!r}, want {key_arn!r}"
    )
    intact_etag = before["ETag"]

    # Poll the read outcome: no API reports when a key-state change reaches S3's decrypt path.
    kms.disable_key(KeyId=key_id)
    assert kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Disabled", (
        "DisableKey returned but DescribeKey does not report the key as Disabled"
    )
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    denied = None
    while time.monotonic() < deadline:
        denied = _client_error(lambda: s3.get_object(Bucket=bucket, Key=obj))
        if denied is not None:
            break
        time.sleep(_POLL_S)
    assert denied is not None, (
        f"GetObject still returned the plaintext {_PROPAGATION_BUDGET_S:.0f}s after the CMK was "
        "disabled — the object is not actually encrypted with that key, so SSE-KMS is a stored "
        "header rather than cryptography"
    )
    code = denied.response.get("Error", {}).get("Code")
    assert code == "KMS.DisabledException", (
        f"expected KMS.DisabledException on the read path of an object whose CMK is disabled, got "
        f"{code!r} — this error is surfaced BY S3 FROM KMS, so anything else means S3 never "
        "called KMS to decrypt"
    )
    message = denied.response.get("Error", {}).get("Message")
    assert message == f"{key_arn} is disabled.", (
        f"the disabled-CMK refusal's message is {message!r}, want {key_arn + ' is disabled.'!r}"
    )
    assert denied.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400, got {denied.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # A disabled key blocks the decrypt, not the metadata.
    head = s3.head_object(Bucket=bucket, Key=obj)
    assert head["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"HeadObject failed while the CMK was disabled: "
        f"{head['ResponseMetadata']['HTTPStatusCode']!r} — only the content should be unreadable"
    )
    assert head["ETag"] == intact_etag, (
        f"the object's ETag changed to {head['ETag']!r} while the key was disabled, want "
        f"{intact_etag!r}"
    )
    assert head["ContentLength"] == len(_PAYLOAD), (
        f"the object's ContentLength is {head['ContentLength']!r} while the key is disabled, want "
        f"{len(_PAYLOAD)}"
    )
    assert head["SSEKMSKeyId"] == key_arn, (
        f"HeadObject reported SSEKMSKeyId {head.get('SSEKMSKeyId')!r}, want {key_arn!r}"
    )

    kms.enable_key(KeyId=key_id)
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    after_body = None
    while time.monotonic() < deadline:
        try:
            after_body = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
            break
        except ClientError:
            time.sleep(_POLL_S)
    assert after_body is not None, (
        f"GetObject still failed {_PROPAGATION_BUDGET_S:.0f}s after the CMK was re-enabled"
    )
    assert after_body == _PAYLOAD, (
        f"the object did not survive the disable/enable cycle: {len(after_body)} bytes came back, "
        f"want {len(_PAYLOAD)} — the ciphertext was replaced rather than merely made unreadable"
    )
    assert s3.head_object(Bucket=bucket, Key=obj)["ETag"] == intact_etag, (
        "the object's ETag changed across the key disable/enable cycle"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
