"""sep-kms-key-scope-sse-kms-object-unreadable-while-its-key-is-disabled-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-sse-kms-object-unreadable-while-its-key-is-disabled-rejected"
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
    """Disabling key A makes GetObject of A's SSE-KMS object fail with KMS.DisabledException while
    it stays listable and head-readable, B's object in the same bucket still reads, and EnableKey
    restores A's bytes.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")
    bucket = _new_bucket(ctx, s3)

    body_a, body_b = b"sep-object-protected-by-key-A", b"sep-object-protected-by-key-B"
    for obj, body, key in (("a.bin", body_a, key_a), ("b.bin", body_b, key_b)):
        s3.put_object(Bucket=bucket, Key=obj, Body=body, ServerSideEncryption="aws:kms", SSEKMSKeyId=key)

    # Positive control: both objects read back their exact bytes under their own key.
    for obj, body, key in (("a.bin", body_a, key_a), ("b.bin", body_b, key_b)):
        got = s3.get_object(Bucket=bucket, Key=obj)
        assert got["Body"].read() == body and got["SSEKMSKeyId"] == key, (
            f"before any key is disabled {obj!r} must read back {body!r} under {key!r}; got "
            f"SSEKMSKeyId={got.get('SSEKMSKeyId')!r}"
        )

    kms.disable_key(KeyId=key_a)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_a))
    refused, refused_msg = _poll(
        lambda: _outcome(lambda: s3.get_object(Bucket=bucket, Key="a.bin")["Body"].read()),
        lambda o: o[0] == "KMS.DisabledException",
        timeout_s=90,
        interval_s=3,
        description="GetObject of key A's object refused after DisableKey",
    )
    assert refused == "KMS.DisabledException", (
        f"GetObject of an object whose SSE-KMS key is disabled must fail with KMS.DisabledException, "
        f"got {refused!r}"
    )
    assert refused_msg == f"{key_a} is disabled.", refused_msg

    # The object still exists: listable, and HeadObject (which does not call KMS) still succeeds.
    listed = {
        o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert listed == {"a.bin", "b.bin"}, f"both objects must stay listable, ListObjectsV2 returned {listed!r}"
    head = s3.head_object(Bucket=bucket, Key="a.bin")
    assert (head["SSEKMSKeyId"], head["ContentLength"]) == (key_a, len(body_a)), (
        f"HeadObject of A's object must still report SSEKMSKeyId={key_a!r} and length {len(body_a)}; "
        f"got {(head.get('SSEKMSKeyId'), head.get('ContentLength'))!r}"
    )

    # The sibling key's object is unaffected.
    sib = s3.get_object(Bucket=bucket, Key="b.bin")["Body"].read()
    assert sib == body_b, f"B's object must still read back {body_b!r} while key A is disabled, got {sib!r}"

    # Repair: re-enable A; the same object returns its exact bytes.
    kms.enable_key(KeyId=key_a)
    back = _poll(
        lambda: _read(s3, bucket, "a.bin"),
        lambda v: isinstance(v, bytes),
        timeout_s=90,
        interval_s=3,
        description="GetObject of key A's object readable again after EnableKey",
    )
    assert back == body_a, f"after EnableKey A's object must read back {body_a!r}, got {back!r}"


def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-s3r-{label}-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _new_bucket(ctx, s3):
    """A private bucket in ctx.region, emptied and deleted at teardown."""
    name = ctx.unique_name("sim2real-sep-s3r-")
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


def _read(s3, bucket, key):
    """The object's bytes, or the error code as a str (never satisfies a bytes predicate)."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"


def _outcome(fn):
    """``("OK", "")`` on success, else the AWS error (code, message); callers poll to an exact code."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message", "")
    return "OK", ""


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll to an observable condition. RAISES on timeout, never returns a failing value."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
