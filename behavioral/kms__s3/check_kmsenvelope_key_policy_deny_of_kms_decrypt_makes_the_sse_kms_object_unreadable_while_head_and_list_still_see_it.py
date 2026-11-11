"""kmsenvelope-key-policy-deny-of-kms-decrypt-makes-the-sse-kms-object-unreadable-while-head-and-list-still-see-it."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "kmsenvelope-key-policy-deny-of-kms-decrypt-makes-the-sse-kms-object-unreadable-while-head-and-list-still-see-it"
)
GROUP = "encryption-rejection"
SERVICES = ["kms", "s3"]

_DENY_SID = "sim2realDenyDecryptOnThisKey"
#: Only Decrypt. PutKeyPolicy / ScheduleKeyDeletion / DescribeKey stay allowed so the deny is
#: reversible and teardown cannot be locked out by the very statement this check installs.
_DENIED_ACTIONS = ["kms:Decrypt"]
_PROPAGATION_BUDGET_S = 60.0
_POLL_S = 3.0


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally.

    Returns the exception rather than its code so the caller asserts presence first and the exact
    code second: a helper that answered a falsy string on success would turn "the target accepted
    something real AWS refuses" into what reads like a naming difference.
    """
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _delete_bucket(s3, bucket: str) -> None:
    """Delete every object this check's own bucket holds, then the bucket. Scoped to a bucket this
    check created, so it can never reach a concurrent run's data."""
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
    bucket = ctx.unique_name("sim2real-behav-kmsenv-deny-").lower()
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "kmsenvelope-deny-decrypt"}]},
    )
    return bucket


def _retire_key(kms, key_id: str) -> None:
    """Schedule the CMK for deletion, the shortest window AWS permits (7 days).

    A KMS key cannot be deleted synchronously: PendingWindowInDays has a 7-day floor, so the key
    sits in PendingDeletion afterwards. That residual is AWS's floor rather than a leak this check
    can close, and it is what every shipped corpus check that mints a CMK does.
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
    """Put the pre-deny policy back. Registered AFTER the key retirement so LIFO runs it FIRST:
    a key left with a live Deny poisons every later read of anything encrypted under it."""
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)


def _listed_keys(s3, bucket: str, prefix: str) -> list[str]:
    """Every object key under prefix, paginated. The bucket belongs to this check alone, so the
    result is a property of the query rather than of who else is using the account."""
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(obj["Key"] for obj in page.get("Contents", []))
    return keys


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A key-policy Deny of kms:Decrypt makes an SSE-KMS object UNREADABLE without making it GONE.

    GetObject fails AccessDenied/403 while HeadObject (same ETag, length, SSEKMSKeyId) and
    ListObjectsV2 still see it, and withdrawing the Deny returns the exact original bytes.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    identity = ctx.client("sts").get_caller_identity()
    account = identity["Account"]

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsenv-deny-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kmsenvelope-deny-decrypt"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    # Registered immediately after the create, before any assertion: the only handle on this key
    # is a server-minted id that no name-prefix cleanup can match.
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    assert created["KeyState"] == "Enabled", (
        f"a freshly created CMK reported KeyState {created['KeyState']!r}, expected 'Enabled'"
    )
    assert key_arn.endswith(f":key/{key_id}") and f":{account}:" in key_arn, (
        f"the minted key ARN {key_arn!r} does not name this account's key {key_id!r}"
    )

    original_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    # Registered AFTER the retirement so LIFO runs the restore FIRST.
    ctx.on_cleanup(lambda: _restore_key_policy(kms, key_id, original_policy))

    bucket = _new_bucket(ctx, s3)
    obj = "envelope/payload.bin"
    payload = b"kmsenvelope-plaintext-only-a-real-decrypt-returns-" + os.urandom(32)

    put = s3.put_object(
        Bucket=bucket, Key=obj, Body=payload,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn, BucketKeyEnabled=False,
    )
    assert put["ServerSideEncryption"] == "aws:kms", (
        f"PutObject reported ServerSideEncryption {put.get('ServerSideEncryption')!r}, "
        "want 'aws:kms'"
    )
    assert put["SSEKMSKeyId"] == key_arn, (
        f"PutObject reported SSEKMSKeyId {put.get('SSEKMSKeyId')!r}, want {key_arn!r} — the object "
        "was not wrapped under the customer key that was asked for"
    )

    # --- POSITIVE CONTROL 1: the exact bytes come back while the key policy permits Decrypt.
    before = s3.get_object(Bucket=bucket, Key=obj)
    before_body = before["Body"].read()
    assert before_body == payload, (
        f"the SSE-KMS object round-tripped to {len(before_body)} bytes, want {len(payload)} — "
        "GetObject did not return what PutObject was given"
    )
    intact_etag = before["ETag"]

    # --- Break exactly one thing: Deny kms:Decrypt on this key, for everyone.
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

    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    refusal = None
    while time.monotonic() < deadline:
        refusal = _client_error(lambda: s3.get_object(Bucket=bucket, Key=obj)["Body"].read())
        if refusal is not None:
            break
        time.sleep(_POLL_S)
    assert refusal is not None, (
        f"GetObject still returned the plaintext {_PROPAGATION_BUDGET_S:.0f}s after kms:Decrypt "
        "was denied on the only key that can unwrap it — the object is not actually encrypted "
        "with that key, so SSE-KMS is a stored header rather than cryptography"
    )
    code = refusal.response.get("Error", {}).get("Code")
    assert code == "AccessDenied", (
        f"expected AccessDenied on the read path of an object whose CMK denies kms:Decrypt, got "
        f"{code!r} — S3 can only produce this by actually calling KMS on the read"
    )
    assert refusal.response["ResponseMetadata"]["HTTPStatusCode"] == 403, (
        f"expected HTTP 403, got {refusal.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    message = refusal.response.get("Error", {}).get("Message")
    expected_message = (
        f"User: {identity['Arn']} is not authorized to perform: kms:Decrypt on resource: "
        f"{key_arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, (
        f"the refusal message must be KMS's explicit-deny verdict {expected_message!r}, got "
        f"{message!r}"
    )

    # --- The effect is scoped to the CONTENT: the object is unreadable, not gone.
    head = s3.head_object(Bucket=bucket, Key=obj)
    assert head["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"HeadObject failed while kms:Decrypt was denied: "
        f"{head['ResponseMetadata']['HTTPStatusCode']!r} — only the content should be unreadable"
    )
    assert head["ETag"] == intact_etag, (
        f"the object's ETag became {head['ETag']!r} while the key was denied, want {intact_etag!r}"
    )
    assert head["ContentLength"] == len(payload), (
        f"the object's ContentLength is {head['ContentLength']!r} while the key is denied, want "
        f"{len(payload)} — the stored ciphertext must be untouched"
    )
    assert head["SSEKMSKeyId"] == key_arn, (
        f"HeadObject reported SSEKMSKeyId {head.get('SSEKMSKeyId')!r}, want {key_arn!r}"
    )
    still_listed = _listed_keys(s3, bucket, "envelope/")
    assert still_listed == [obj], (
        f"the unreadable object must still be listable; ListObjectsV2 under 'envelope/' returned "
        f"{still_listed!r}, want exactly [{obj!r}]"
    )

    # --- POSITIVE CONTROL 2: withdraw the one statement and the EXACT original bytes return.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=original_policy)
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    after_body = None
    while time.monotonic() < deadline:
        try:
            after_body = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
            break
        except ClientError:
            time.sleep(_POLL_S)
    assert after_body is not None, (
        f"GetObject still failed {_PROPAGATION_BUDGET_S:.0f}s after the Deny of kms:Decrypt was "
        "withdrawn — access was not restored"
    )
    assert after_body == payload, (
        f"the object did not survive losing and regaining its key: {len(after_body)} bytes came "
        f"back, want {len(payload)} — the ciphertext was replaced rather than merely made "
        "unreadable"
    )
    assert s3.head_object(Bucket=bucket, Key=obj)["ETag"] == intact_etag, (
        "the object's ETag changed across the deny/restore cycle, so the bytes on the other side "
        "are not the bytes that were written"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
