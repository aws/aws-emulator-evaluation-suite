"""bucket-key-switches-the-kms-encryption-context-from-object-arn-to-bucket-arn."""
from __future__ import annotations

# With an S3 Bucket Key, S3's KMS requests carry the encryption context aws:s3:arn = the BUCKET ARN;
# without one, the OBJECT ARN (AmazonS3 userguide, UsingKMSEncryption.html and bucket-key.html).

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-key-switches-the-kms-encryption-context-from-object-arn-to-bucket-arn"
GROUP = "server-side"
SERVICES = ["kms", "s3"]

_DENY_SID = "sim2realRequireBucketArnContext"
_DENIED_ACTIONS = [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKey*",
    "kms:ReEncrypt*",
]


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _restore_key_policy(kms, key_id: str, policy: str) -> None:
    """Put back the permissive policy. Registered so it runs BEFORE the key deletion (cleanup is
    LIFO): a ScheduleKeyDeletion issued while an over-broad deny is live would itself be at risk."""
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)


def _delete_bucket(s3, bucket: str, keys: list[str]) -> None:
    """Delete exactly the objects this check wrote, then the bucket. Scoped to this check's own
    keys, never a prefix sweep, which could delete objects of concurrent runs."""
    for key in keys:
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("NoSuchKey", "NoSuchBucket"):
                raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _put_outcome(s3, bucket: str, key: str, body: bytes):
    """Return (None, ETag, None) on success or (Error.Code, http status, Error.Message) on refusal."""
    try:
        resp = s3.put_object(Bucket=bucket, Key=key, Body=body)
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message"),
        )
    return None, resp.get("ETag"), None


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 5.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or RAISES on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _head_code(s3, bucket: str, key: str):
    """Return None if the object exists, else the HTTP status of the failed HeadObject."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return None


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Enabling an S3 Bucket Key really changes the KMS request S3 makes, not just a reported flag.

    A CMK denying crypto unless aws:s3:arn is the BUCKET ARN accepts SSE-KMS writes with the bucket
    key on, refuses them with it off (the OBJECT ARN is sent), and accepts them once restored.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]

    bucket = ctx.unique_name("sim2real-behav-kms-bucketkey-").lower()
    create_args = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the only region CreateBucket rejects a LocationConstraint for.
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_args)
    key_on = "written-with-bucket-key"
    key_off = "written-without-bucket-key"
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket, [key_on, key_off]))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kms-s3-bucket-key-context"}]},
    )
    bucket_arn = f"arn:{partition}:s3:::{bucket}"

    cmk = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-bucketkey-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-s3-bucket-key-context"}],
    )["KeyMetadata"]
    key_arn, key_id = cmk["Arn"], cmk["KeyId"]
    ctx.on_cleanup(lambda: _teardown_key(kms, key_arn))
    original_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    # Registered AFTER the deletion so LIFO runs it FIRST.
    ctx.on_cleanup(lambda: _restore_key_policy(kms, key_id, original_policy))

    # --- The one constraint: cryptographic use only when the context names the BUCKET. The denied
    # action list deliberately excludes kms:PutKeyPolicy and kms:ScheduleKeyDeletion so the key
    # stays manageable and this is reversible (a negated condition also fires on an absent key).
    policy = json.loads(original_policy)
    policy["Statement"].append(
        {
            "Sid": _DENY_SID,
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": _DENIED_ACTIONS,
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {"kms:EncryptionContext:aws:s3:arn": bucket_arn}
            },
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    readback = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert any(s.get("Sid") == _DENY_SID for s in readback["Statement"]), (
        f"the {_DENY_SID} statement was not persisted, so the rest of this check would grade "
        f"nothing: {readback!r}"
    )

    def set_bucket_key(enabled: bool) -> None:
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": key_arn,
                        },
                        "BucketKeyEnabled": enabled,
                    }
                ]
            },
        )
        rules = s3.get_bucket_encryption(Bucket=bucket)[
            "ServerSideEncryptionConfiguration"
        ]["Rules"]
        assert len(rules) == 1, f"expected exactly one default-encryption rule, got {rules!r}"
        assert rules[0]["BucketKeyEnabled"] is enabled, (
            f"GetBucketEncryption must report BucketKeyEnabled={enabled}, got "
            f"{rules[0].get('BucketKeyEnabled')!r}"
        )

    # --- Positive control: bucket key ON, the write is permitted.
    set_bucket_key(True)
    body_on = b"bucket-key-on-" + os.urandom(24)
    outcome = _poll_until(
        lambda: _put_outcome(s3, bucket, key_on, body_on),
        lambda pair: pair[0] is None,
        timeout_s=120,
        what=(
            "PutObject to be permitted with BucketKeyEnabled=true — the key policy requires the "
            f"encryption context aws:s3:arn to equal {bucket_arn}"
        ),
    )
    assert outcome[0] is None, outcome

    # --- Terminal reads AT THE CONSUMER: the object is really there, really SSE-KMS under this
    # CMK, and really bucket-keyed.
    head_on = s3.head_object(Bucket=bucket, Key=key_on)
    assert head_on["ServerSideEncryption"] == "aws:kms", (
        f"expected ServerSideEncryption 'aws:kms', got {head_on.get('ServerSideEncryption')!r}"
    )
    assert head_on["SSEKMSKeyId"] == key_arn, (
        f"the object must be encrypted under {key_arn!r}, got {head_on.get('SSEKMSKeyId')!r}"
    )
    assert head_on["BucketKeyEnabled"] is True, (
        f"the object written while the bucket key was on must report BucketKeyEnabled=True, got "
        f"{head_on.get('BucketKeyEnabled')!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key_on)["Body"].read() == body_on, (
        "GetObject must return the exact bytes written through the bucket-keyed SSE-KMS path"
    )

    # --- Break exactly one thing: turn the bucket key OFF. Same bucket, same CMK, same key
    # policy, same principal — only the encryption context S3 sends changes.
    set_bucket_key(False)
    body_off = b"bucket-key-off-" + os.urandom(24)
    code, status, message = _poll_until(
        lambda: _put_outcome(s3, bucket, key_off, body_off),
        lambda pair: pair[0] is not None,
        timeout_s=120,
        what=(
            "PutObject to start being refused after BucketKeyEnabled=false — S3 must switch to "
            "sending the OBJECT ARN as the encryption context, which the key policy denies"
        ),
    )
    assert status == 403, (
        f"a KMS refusal must surface from S3 as HTTP 403; got status {status!r} with code {code!r}"
    )
    assert code == "AccessDenied", (
        f"the refusal must be an access denial naming the key policy decision, expected "
        f"'AccessDenied', got {code!r}"
    )
    # S3 relays KMS's verdict on the GenerateDataKey it made with the OBJECT ARN as context.
    expected_message = (
        f"User: {caller['Arn']} is not authorized to perform: kms:GenerateDataKey on resource: "
        f"{key_arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, (
        f"the refusal message must be KMS's explicit-deny verdict {expected_message!r}, got "
        f"{message!r}"
    )

    # --- Effect absent, observed at the consumer by an independent read.
    assert _head_code(s3, bucket, key_off) == 404, (
        f"the refused write must have left NO object at {key_off!r}; head_object returned "
        f"{_head_code(s3, bucket, key_off)!r}"
    )
    # And the refusal was about the new write, not about the key going bad: the already-written
    # bucket-keyed object is still readable, which requires a successful kms:Decrypt.
    assert s3.get_object(Bucket=bucket, Key=key_on)["Body"].read() == body_on, (
        "the bucket-keyed object must still be readable while the non-bucket-keyed write is "
        "refused — reads go through the bucket ARN context and stay permitted"
    )

    # --- Restore the one broken thing and demand the withheld write.
    set_bucket_key(True)
    restored = _poll_until(
        lambda: _put_outcome(s3, bucket, key_off, body_off),
        lambda pair: pair[0] is None,
        timeout_s=120,
        what="the byte-identical PutObject to succeed once the bucket key is enabled again",
    )
    assert restored[0] is None, (
        f"positive control: re-enabling the bucket key must make the identical PutObject succeed, "
        f"got code {restored[0]!r}"
    )
    head_restored = s3.head_object(Bucket=bucket, Key=key_off)
    assert head_restored["BucketKeyEnabled"] is True, (
        f"the object written after the bucket key was restored must report BucketKeyEnabled=True, "
        f"got {head_restored.get('BucketKeyEnabled')!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key_off)["Body"].read() == body_off, (
        "GetObject must return the exact bytes of the write that was refused a moment earlier"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
