"""sep-kms-key-scope-sse-kms-write-under-a-disabled-key-rejected-and-no-object-created."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-sse-kms-write-under-a-disabled-key-rejected-and-no-object-created"
GROUP = "key-separation"
SERVICES = ["kms", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SSE-KMS PutObject and CopyObject under disabled key A fail KMS.DisabledException and store
    nothing, while the same PutObject under enabled key B succeeds; re-enabling A makes it succeed.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")
    bucket = _new_bucket(ctx, s3)
    body = b"sep-write-path-payload"

    s3.put_object(Bucket=bucket, Key="src/source.bin", Body=body)

    kms.disable_key(KeyId=key_a)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_a))
    state = kms.describe_key(KeyId=key_a)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"key A must be Disabled before the write is attempted, got {state!r}"

    # Positive control first: the same PutObject under enabled key B works.
    s3.put_object(Bucket=bucket, Key="ok/under-b.bin", Body=body,
                  ServerSideEncryption="aws:kms", SSEKMSKeyId=key_b)
    got_b = s3.get_object(Bucket=bucket, Key="ok/under-b.bin")
    assert got_b["Body"].read() == body and got_b["SSEKMSKeyId"] == key_b, (
        f"PutObject under enabled key B must read back {body!r} under {key_b!r}; got "
        f"SSEKMSKeyId={got_b.get('SSEKMSKeyId')!r}"
    )

    disabled_message = f"{key_a} is disabled."
    put_code, put_message = _rejected(lambda: s3.put_object(
        Bucket=bucket, Key="denied/put.bin", Body=body,
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_a))
    assert put_code == "KMS.DisabledException", (
        f"PutObject with SSE-KMS under the disabled key A must fail with KMS.DisabledException, "
        f"got {put_code!r}"
    )
    assert put_message == disabled_message, (
        f"PutObject's refusal message must be {disabled_message!r}, got {put_message!r}"
    )
    copy_code, copy_message = _rejected(lambda: s3.copy_object(
        Bucket=bucket, Key="denied/copy.bin", CopySource={"Bucket": bucket, "Key": "src/source.bin"},
        ServerSideEncryption="aws:kms", SSEKMSKeyId=key_a))
    assert copy_code == "KMS.DisabledException", (
        f"CopyObject into SSE-KMS under the disabled key A must fail with KMS.DisabledException, "
        f"got {copy_code!r}"
    )
    assert copy_message == disabled_message, (
        f"CopyObject's refusal message must be {disabled_message!r}, got {copy_message!r}"
    )

    for obj in ("denied/put.bin", "denied/copy.bin"):
        head = _rejected_code(lambda o=obj: s3.head_object(Bucket=bucket, Key=o))
        assert head == "404", f"no object may exist at {obj!r} after the refused write; HeadObject gave {head!r}"
    denied = [
        o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="denied/")
        for o in page.get("Contents", [])
    ]
    assert denied == [], f"the refused writes must leave nothing under 'denied/', found {denied!r}"

    kms.enable_key(KeyId=key_a)
    s3.put_object(Bucket=bucket, Key="denied/put.bin", Body=body,
                  ServerSideEncryption="aws:kms", SSEKMSKeyId=key_a)
    got_a = s3.get_object(Bucket=bucket, Key="denied/put.bin")
    assert got_a["Body"].read() == body and got_a["SSEKMSKeyId"] == key_a, (
        f"after EnableKey the same PutObject must read back {body!r} under {key_a!r}; got "
        f"SSEKMSKeyId={got_a.get('SSEKMSKeyId')!r}"
    )


def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-s3w-{label}-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _new_bucket(ctx, s3):
    """A private bucket in ctx.region, emptied and deleted at teardown."""
    name = ctx.unique_name("sim2real-sep-s3w-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _teardown():
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown)
    return name


def _rejected(fn):
    """(code, message) of a call real AWS refuses; an unexpected SUCCESS raises with the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _rejected_code(fn):
    """The AWS error code of a call real AWS refuses; an unexpected SUCCESS raises."""
    return _rejected(fn)[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
