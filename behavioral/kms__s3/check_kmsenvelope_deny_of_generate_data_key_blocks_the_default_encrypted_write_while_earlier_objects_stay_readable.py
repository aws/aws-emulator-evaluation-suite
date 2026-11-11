"""kmsenvelope-deny-of-generate-data-key-blocks-the-default-encrypted-write-while-earlier-objects-stay-readable."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "kmsenvelope-deny-of-generate-data-key-blocks-the-default-encrypted-write-while-earlier-objects-stay-readable"
)
GROUP = "encryption-rejection"
SERVICES = ["kms", "s3"]

_DENY_SID = "sim2realDenyGenerateDataKey"
#: Only the key-minting actions S3 needs on the WRITE path. kms:Decrypt is deliberately left
#: permitted, which is what makes the read-side positive control below discriminating, and the
#: administrative actions stay permitted so the deny is reversible.
_DENIED_ACTIONS = ["kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext"]
_PROPAGATION_BUDGET_S = 60.0
_POLL_S = 3.0


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


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
    bucket = ctx.unique_name("sim2real-behav-kmsenv-default-").lower()
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kmsenvelope-default-encryption"}]},
    )
    return bucket


def _retire_key(kms, key_id: str) -> None:
    """Schedule the CMK for deletion with the 7-day minimum window AWS enforces.

    KMS has no synchronous key delete, so the key sits in PendingDeletion afterwards. That
    residual is AWS's floor, not a leak this check can close.
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


def _restore_key_policy(kms, key_id: str, policy: str) -> None:
    """Put the pre-deny policy back. Registered AFTER the key retirement so LIFO runs it FIRST: a
    key left unable to mint data keys poisons every later write in this shared account."""
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """With bucket-default SSE-KMS, a PutObject without encryption headers reports the bucket's key;
    denying only kms:GenerateDataKey refuses the next write AccessDenied/403 with the exact message and
    stores nothing, earlier objects stay readable, and removing the Deny restores the write."""
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-default-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-default-encryption"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    original_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    # Registered AFTER the retirement so LIFO runs the restore FIRST.
    ctx.on_cleanup(lambda: _restore_key_policy(kms, key_id, original_policy))

    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={"Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_arn},
            # No bucket key: S3 must call KMS on every request rather than caching a data key,
            # which is what makes the deny below observable on the very next write.
            "BucketKeyEnabled": False,
        }]},
    )
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    assert len(rules) == 1, f"expected exactly one default-encryption rule, got {rules!r}"
    assert rules[0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] == key_arn, (
        f"the bucket's default encryption names "
        f"{rules[0]['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID')!r}, want "
        f"{key_arn!r}"
    )

    early = "envelope/written-before-the-deny.bin"
    early_payload = b"kmsenvelope-default-encrypted-" + os.urandom(32)

    # --- POSITIVE CONTROL 1: a plain PutObject, no encryption arguments, is sealed with the CMK.
    put = s3.put_object(Bucket=bucket, Key=early, Body=early_payload)
    assert put["ServerSideEncryption"] == "aws:kms", (
        f"a headerless PutObject into a bucket defaulting to aws:kms reported "
        f"{put.get('ServerSideEncryption')!r} — the bucket default was not applied"
    )
    assert put["SSEKMSKeyId"] == key_arn, (
        f"the default-encrypted object reported SSEKMSKeyId {put.get('SSEKMSKeyId')!r}, want "
        f"{key_arn!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=early)["Body"].read() == early_payload, (
        f"the default-encrypted object did not round-trip its {len(early_payload)} bytes"
    )

    # --- Break exactly one thing: the CMK may no longer mint data keys. Decrypt stays permitted.
    denied_policy = json.loads(original_policy)
    denied_policy["Statement"].append({
        "Sid": _DENY_SID,
        "Effect": "Deny",
        "Principal": {"AWS": "*"},
        "Action": _DENIED_ACTIONS,
        "Resource": "*",
    })
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(denied_policy))
    readback = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert any(s.get("Sid") == _DENY_SID for s in readback["Statement"]), (
        f"the {_DENY_SID} statement was not persisted, so the rest of this check would grade "
        f"nothing: {readback!r}"
    )

    # Each attempt writes to its OWN key, so the key that is finally refused is one no earlier,
    # still-permitted attempt could have created: the 404 below then grades the refusal rather than
    # the propagation delay.
    blocked_payload = b"kmsenvelope-should-never-land-" + os.urandom(32)
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    refusal, blocked, attempt = None, None, 0
    while time.monotonic() < deadline:
        blocked = f"envelope/written-after-the-deny-{attempt}.bin"
        refusal = _client_error(
            lambda: s3.put_object(Bucket=bucket, Key=blocked, Body=blocked_payload)
        )
        if refusal is not None:
            break
        attempt += 1
        time.sleep(_POLL_S)
    assert refusal is not None, (
        f"PutObject still succeeded {_PROPAGATION_BUDGET_S:.0f}s after kms:GenerateDataKey was "
        "denied on the bucket's default CMK — S3 is not minting a data key per write, so the "
        "default encryption is a stored setting rather than cryptography"
    )
    code = refusal.response.get("Error", {}).get("Code")
    assert code == "AccessDenied", (
        f"expected AccessDenied when S3 cannot mint a data key for a default-encrypted write, got "
        f"{code!r}"
    )
    assert refusal.response["ResponseMetadata"]["HTTPStatusCode"] == 403, (
        f"expected HTTP 403, got {refusal.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    message = refusal.response.get("Error", {}).get("Message")
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: kms:GenerateDataKey on resource: "
        f"{key_arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, (
        f"the refusal message must be KMS's explicit-deny verdict {expected_message!r}, got "
        f"{message!r}"
    )

    # --- Effect absent: the refused write stored nothing.
    missing = _client_error(lambda: s3.head_object(Bucket=bucket, Key=blocked))
    assert missing is not None, (
        f"HeadObject found {blocked!r} after the write was refused — a rejected write must store "
        "nothing"
    )
    assert missing.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the object the refused write did not create, got "
        f"{missing.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- The deny is scoped to the WRITE path: kms:Decrypt was untouched, so what was already
    # sealed is still readable byte for byte.
    assert s3.get_object(Bucket=bucket, Key=early)["Body"].read() == early_payload, (
        "the object written before the deny must still return its exact bytes — only the minting "
        "of NEW data keys was withdrawn"
    )

    # --- POSITIVE CONTROL 2: withdraw the statement and the refused write must land, and land
    # encrypted under the same CMK.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=original_policy)
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    restored = None
    while time.monotonic() < deadline:
        try:
            restored = s3.put_object(Bucket=bucket, Key=blocked, Body=blocked_payload)
            break
        except ClientError:
            time.sleep(_POLL_S)
    assert restored is not None, (
        f"PutObject still failed {_PROPAGATION_BUDGET_S:.0f}s after the Deny of "
        "kms:GenerateDataKey was withdrawn — access was not restored"
    )
    assert restored["SSEKMSKeyId"] == key_arn, (
        f"the restored write reported SSEKMSKeyId {restored.get('SSEKMSKeyId')!r}, want {key_arn!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=blocked)["Body"].read() == blocked_payload, (
        f"the write refused a moment earlier did not round-trip its {len(blocked_payload)} bytes "
        "once the key could mint data keys again"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
