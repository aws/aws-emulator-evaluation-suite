"""kmsenvelope-via-service-condition-permits-the-s3-envelope-path-and-denies-the-same-callers-direct-kms-use."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "kmsenvelope-via-service-condition-permits-the-s3-envelope-path-and-denies-the-same-callers-direct-kms-use"
)
GROUP = "encryption-rejection"
SERVICES = ["kms", "s3"]

_PROPAGATION_BUDGET_S = 60.0
_POLL_S = 3.0
#: Kept unconditional in every policy this check installs, so the key stays manageable and
#: teardown can never be locked out by the condition under test.
_ADMIN_ACTIONS = [
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
    "kms:EnableKey",
    "kms:DisableKey",
    "kms:TagResource",
    "kms:ListResourceTags",
]
_CRYPTO_ACTIONS = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*"]


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
    bucket = ctx.unique_name("sim2real-behav-kmsenv-via-").lower()
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kmsenvelope-via-service"}]},
    )
    return bucket


def _retire_key(kms, key_id: str) -> None:
    """Schedule the CMK for deletion with the 7-day minimum window AWS enforces.

    kms:ScheduleKeyDeletion is granted unconditionally by every policy this check installs, so
    teardown does not depend on the condition under test.
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


def _policy(root_arn: str, via_service: str | None) -> str:
    """The key policy: admin actions always, cryptographic actions either gated on kms:ViaService
    or (when via_service is None) ungated. The two differ in exactly one Condition block."""
    crypto = {
        "Sid": "CryptoUse",
        "Effect": "Allow",
        "Principal": {"AWS": root_arn},
        "Action": _CRYPTO_ACTIONS,
        "Resource": "*",
    }
    if via_service is not None:
        crypto["Condition"] = {"StringEquals": {"kms:ViaService": via_service}}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Admin", "Effect": "Allow", "Principal": {"AWS": root_arn},
             "Action": _ADMIN_ACTIONS, "Resource": "*"},
            crypto,
        ],
    })


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Under a kms:ViaService=S3 key policy, SSE-KMS writes and reads through S3 round-trip while
    the same caller's direct GenerateDataKey is denied AccessDeniedException/400; removing the
    condition makes the direct call succeed, pinning the denial to the condition.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    identity = ctx.client("sts").get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    root_arn = f"arn:{partition}:iam::{identity['Account']}:root"
    # Derived from the region under test: a literal host would make this pass in one region only.
    via_service = f"s3.{ctx.region}.amazonaws.com"

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-via-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=_policy(root_arn, via_service),
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-via-service"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    live = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    conditions = [s.get("Condition") for s in live["Statement"] if s.get("Sid") == "CryptoUse"]
    assert conditions == [{"StringEquals": {"kms:ViaService": via_service}}], (
        f"the ViaService condition was not persisted on the key policy ({conditions!r}), so the "
        "rest of this check would grade nothing"
    )

    bucket = _new_bucket(ctx, s3)
    obj = "envelope/via-service.bin"
    payload = b"kmsenvelope-via-service-payload-" + os.urandom(40)

    # Through S3 the condition is satisfied: the write needs GenerateDataKey and the read needs
    # Decrypt, both from the conditioned statement.
    put = s3.put_object(
        Bucket=bucket, Key=obj, Body=payload,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn, BucketKeyEnabled=False,
    )
    assert put["SSEKMSKeyId"] == key_arn, (
        f"PutObject reported SSEKMSKeyId {put.get('SSEKMSKeyId')!r}, want {key_arn!r}"
    )
    read_back = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert read_back == payload, (
        f"the SSE-KMS object round-tripped to {len(read_back)} bytes, want {len(payload)} — S3's "
        "GenerateDataKey/Decrypt must be permitted while kms:ViaService matches"
    )

    refusal = _client_error(lambda: kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256"))
    assert refusal is not None, (
        "GenerateDataKey succeeded when called directly on a key whose policy permits it only "
        f"with kms:ViaService == {via_service!r} — the condition is not being evaluated, so any "
        "caller can take data keys out of the service path the policy confines them to"
    )
    code = refusal.response.get("Error", {}).get("Code")
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a direct GenerateDataKey outside the permitted "
        f"service path, got {code!r}"
    )
    assert refusal.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400, got {refusal.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    message = refusal.response.get("Error", {}).get("Message")
    expected_message = (
        f"User: {identity['Arn']} is not authorized to perform: kms:GenerateDataKey on resource: "
        f"{key_arn} because no resource-based policy allows the kms:GenerateDataKey action"
    )
    assert message == expected_message, (
        f"the direct call's refusal must name the missing key-policy allow, expected "
        f"{expected_message!r}, got {message!r}"
    )

    # The service path keeps working while the direct path is denied.
    second = "envelope/via-service-2.bin"
    s3.put_object(
        Bucket=bucket, Key=second, Body=payload,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn, BucketKeyEnabled=False,
    )
    assert s3.get_object(Bucket=bucket, Key=second)["Body"].read() == payload, (
        "the S3 envelope path must keep working while the direct KMS call is denied — the denial "
        "is about the request path, not about the key"
    )

    # Key policy changes propagate eventually, so the direct call is retried within a budget.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=_policy(root_arn, None))
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    direct = None
    while time.monotonic() < deadline:
        try:
            direct = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256")
            break
        except ClientError:
            time.sleep(_POLL_S)
    assert direct is not None, (
        f"GenerateDataKey still failed {_PROPAGATION_BUDGET_S:.0f}s after the kms:ViaService "
        "condition was removed, so the earlier denial cannot be attributed to that condition"
    )
    assert len(direct["Plaintext"]) == 32, (
        f"the now-permitted direct GenerateDataKey returned a {len(direct['Plaintext'])}-byte key, "
        "want 32"
    )
    unwrapped = kms.decrypt(CiphertextBlob=direct["CiphertextBlob"], KeyId=key_arn)
    assert unwrapped["Plaintext"] == direct["Plaintext"], (
        "the data key handed out on the direct path does not unwrap to itself, so the key is not "
        "usable outside the service path even after the condition was withdrawn"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
