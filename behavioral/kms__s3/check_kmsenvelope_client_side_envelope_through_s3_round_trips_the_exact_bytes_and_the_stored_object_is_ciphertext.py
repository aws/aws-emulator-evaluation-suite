"""kmsenvelope-client-side-envelope-through-s3-round-trips-the-exact-bytes-and-the-stored-object-is-ciphertext."""
from __future__ import annotations

import base64
import json
import os
import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from behavioral_harness import tags

CHECK = (
    "kmsenvelope-client-side-envelope-through-s3-round-trips-the-exact-bytes-and-the-stored-object-is-ciphertext"
)
GROUP = "envelope-encryption"
SERVICES = ["kms", "s3"]

_NONCE_LEN = 12  # AES-GCM's standard nonce length.
_KEY_LEN = 32  # KMS AES_256 data keys.


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
    bucket = ctx.unique_name("sim2real-behav-kmsenv-wrap-").lower()
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kmsenvelope-client-side"}]},
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A KMS data key seals bytes locally; S3 stores only ciphertext plus the wrapped key, and
    Decrypt of that wrapped key under the same encryption context recovers the exact plaintext.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-wrap-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-client-side"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))

    bucket = _new_bucket(ctx, s3)
    obj = "envelope/sealed.bin"
    payload = b"kmsenvelope-customer-bytes-" + os.urandom(64) + b"-end"
    # The context is scoped to resources only this run owns, so it cannot collide with a sibling
    # run in the same account.
    enc_context = {"purpose": "sim2real-kmsenvelope", "bucket": bucket, "object": obj}
    aad = json.dumps(enc_context, sort_keys=True).encode()

    dk = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256", EncryptionContext=enc_context)
    assert len(dk["Plaintext"]) == _KEY_LEN, (
        f"GenerateDataKey(AES_256) returned a {len(dk['Plaintext'])}-byte plaintext key, want "
        f"{_KEY_LEN}"
    )
    assert dk["KeyId"] == key_arn, (
        f"GenerateDataKey reported KeyId {dk.get('KeyId')!r}, want the full ARN {key_arn!r}"
    )
    assert dk["CiphertextBlob"] != dk["Plaintext"], (
        "GenerateDataKey returned the same bytes for CiphertextBlob and Plaintext — the wrapped "
        "key must be the key encrypted under the CMK, not a copy of it"
    )
    assert dk["Plaintext"] not in dk["CiphertextBlob"], (
        "the plaintext data key appears verbatim inside the CiphertextBlob, so the 'wrapped' key "
        "is not wrapped at all"
    )

    nonce = os.urandom(_NONCE_LEN)
    sealed = AESGCM(dk["Plaintext"]).encrypt(nonce, payload, aad)
    wrapped_key_b64 = base64.b64encode(dk["CiphertextBlob"]).decode()
    stored = nonce + sealed
    # Drop the plaintext key: everything below has only what a consumer reading S3 would have.
    del dk

    s3.put_object(
        Bucket=bucket, Key=obj, Body=stored,
        Metadata={"wrapped-key": wrapped_key_b64,
                  "enc-context": base64.b64encode(aad).decode()},
    )

    got = s3.get_object(Bucket=bucket, Key=obj)
    got_body = got["Body"].read()
    assert got_body == stored, (
        f"S3 returned {len(got_body)} bytes, want the {len(stored)} that were uploaded — the "
        "sealed envelope did not survive storage"
    )
    assert payload not in got_body, (
        "the object stored in S3 contains the plaintext verbatim: the payload was never actually "
        "encrypted with the data key"
    )
    assert got["Metadata"]["wrapped-key"] == wrapped_key_b64, (
        f"the wrapped key in the object's metadata came back as "
        f"{got['Metadata'].get('wrapped-key')!r}, want {wrapped_key_b64!r} — without it the "
        "envelope is unrecoverable"
    )

    recovered_blob = base64.b64decode(got["Metadata"]["wrapped-key"])
    recovered_context = json.loads(base64.b64decode(got["Metadata"]["enc-context"]))
    assert recovered_context == enc_context, (
        f"the encryption context stored beside the object came back as {recovered_context!r}, "
        f"want {enc_context!r}"
    )
    unwrapped = kms.decrypt(
        CiphertextBlob=recovered_blob, KeyId=key_arn, EncryptionContext=recovered_context
    )
    assert unwrapped["KeyId"] == key_arn, (
        f"Decrypt reported KeyId {unwrapped.get('KeyId')!r}, want {key_arn!r} — the blob must "
        "resolve to the CMK that wrapped it"
    )
    assert len(unwrapped["Plaintext"]) == _KEY_LEN, (
        f"Decrypt returned a {len(unwrapped['Plaintext'])}-byte data key, want {_KEY_LEN}"
    )
    opened = AESGCM(unwrapped["Plaintext"]).decrypt(
        got_body[:_NONCE_LEN], got_body[_NONCE_LEN:], aad
    )
    assert opened == payload, (
        f"the envelope round-tripped to {len(opened)} bytes, want {len(payload)} — the key KMS "
        "returned for the wrapped blob does not open what the plaintext key sealed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
