"""kmsenvelope-mismatched-encryption-context-is-refused-when-unwrapping-the-stored-data-key."""
from __future__ import annotations

import base64
import json
import os
import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from behavioral_harness import tags

CHECK = "kmsenvelope-mismatched-encryption-context-is-refused-when-unwrapping-the-stored-data-key"
GROUP = "encryption-rejection"
SERVICES = ["kms", "s3"]

_NONCE_LEN = 12
_KEY_LEN = 32


def _client_error(fn, accepted):
    """Call fn(); return the ClientError it raised. A normal return fails with ``accepted``:
    the target took what real AWS refuses, which is never an error-code naming difference."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(accepted)


def _delete_bucket(s3, bucket: str) -> None:
    """Delete every object this check's own bucket holds, then the bucket."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely named, sim2real-tagged bucket in ctx.region and register its teardown."""
    bucket = ctx.unique_name("sim2real-behav-kmsenv-ctx-").lower()
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kmsenvelope-context-mismatch"}]},
    )
    return bucket


def _retire_key(kms, key_id: str) -> None:
    """Schedule the CMK for deletion with the 7-day minimum window AWS enforces.

    KMS has no synchronous key delete, so the key stays in PendingDeletion afterwards.
    """
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code != "ThrottlingException" or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Decrypting a wrapped data key stored beside an S3 object with one encryption-context value
    changed is refused InvalidCiphertextException/400, the object stays sealed, and the same
    Decrypt with the right context recovers a key that opens the payload byte for byte.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-ctx-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-context-mismatch"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))

    bucket = _new_bucket(ctx, s3)
    obj = "envelope/context-bound.bin"
    payload = b"kmsenvelope-context-bound-payload-" + os.urandom(48)
    enc_context = {"purpose": "sim2real-kmsenvelope", "bucket": bucket, "object": obj}
    aad = json.dumps(enc_context, sort_keys=True).encode()

    dk = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256", EncryptionContext=enc_context)
    wrapped = dk["CiphertextBlob"]
    nonce = os.urandom(_NONCE_LEN)
    stored = nonce + AESGCM(dk["Plaintext"]).encrypt(nonce, payload, aad)
    del dk  # only the object and its wrapped key are used from here on

    s3.put_object(Bucket=bucket, Key=obj, Body=stored,
                  Metadata={"wrapped-key": base64.b64encode(wrapped).decode()})
    fetched = s3.get_object(Bucket=bucket, Key=obj)
    fetched_body = fetched["Body"].read()
    assert fetched_body == stored, (
        f"S3 returned {len(fetched_body)} bytes, want the {len(stored)} that were uploaded"
    )

    # --- Break exactly one thing: one value of the encryption context.
    wrong_context = dict(enc_context, object=obj + ".other")
    refusal = _client_error(
        lambda: kms.decrypt(
            CiphertextBlob=wrapped, KeyId=key_arn, EncryptionContext=wrong_context
        ),
        accepted=(
            f"Decrypt returned a data key for a blob wrapped under {enc_context!r} when asked "
            f"with {wrong_context!r} — the encryption context is not bound to the ciphertext, so "
            "any caller who can reach the key can unwrap another context's data"
        ),
    )
    code = refusal.response.get("Error", {}).get("Code")
    assert code == "InvalidCiphertextException", (
        f"expected InvalidCiphertextException for a mismatched encryption context, got {code!r}"
    )
    message = refusal.response.get("Error", {}).get("Message")
    # KMS sends this refusal with no message text; botocore reports the absent text as "".
    assert message == "", f"InvalidCiphertextException message was {message!r}, expected ''"
    assert refusal.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400, got {refusal.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # A random key of the right length must not open the object, so the stored bytes really are
    # ciphertext.
    still_there = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert still_there == stored, (
        f"the refused unwrap changed the stored object: {len(still_there)} bytes now, want "
        f"{len(stored)}"
    )
    opened_with_wrong_key = None
    try:
        opened_with_wrong_key = AESGCM(os.urandom(_KEY_LEN)).decrypt(
            still_there[:_NONCE_LEN], still_there[_NONCE_LEN:], aad
        )
    except InvalidTag:
        pass
    assert opened_with_wrong_key is None, (
        "the sealed payload opened under a random data key, so the object in S3 is not actually "
        "encrypted with the key KMS wrapped"
    )

    # Positive control: the same unwrap with the right context recovers the key.
    unwrapped = kms.decrypt(CiphertextBlob=wrapped, KeyId=key_arn, EncryptionContext=enc_context)
    assert len(unwrapped["Plaintext"]) == _KEY_LEN, (
        f"the matching-context unwrap returned a {len(unwrapped['Plaintext'])}-byte key, want "
        f"{_KEY_LEN} — the refusal above must be about the context, not about the blob"
    )
    opened = AESGCM(unwrapped["Plaintext"]).decrypt(
        still_there[:_NONCE_LEN], still_there[_NONCE_LEN:], aad
    )
    assert opened == payload, (
        f"positive control: the recovered key opened the object to {len(opened)} bytes, want "
        f"{len(payload)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
