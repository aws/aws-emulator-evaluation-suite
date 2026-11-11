"""object-key-1024-bytes-boundary-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-key-1024-bytes-boundary-rejected"
GROUP = 'errors'
SERVICES = ['s3']
KEY_TOO_LONG_MESSAGE = 'Your key is too long'


# ===== helpers (self-contained) =====
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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The S3 object-key limit is exactly 1024 UTF-8 BYTES: 1024 is accepted, 1025 is KeyTooLongError.

    The limit counts bytes, not characters, so a 1024-character multibyte key is refused; both sides
    of the boundary are asserted.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # --- Control: exactly 1024 single-byte characters is legal, stored, readable and listable.
    at_limit = "a" * 1024
    assert len(at_limit.encode("utf-8")) == 1024, (
        f"test setup error: expected a 1024-byte key, got {len(at_limit.encode('utf-8'))}"
    )
    s3.put_object(Bucket=bucket, Key=at_limit, Body=b"at-limit")
    got = s3.get_object(Bucket=bucket, Key=at_limit)["Body"].read()
    assert got == b"at-limit", f"1024-byte key did not round-trip its body, got {got!r}"
    listed = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert at_limit in listed, "a 1024-byte key was stored but is missing from ListObjectsV2"

    # --- Control: the limit is counted in BYTES. 512 two-byte characters == 1024 bytes == legal.
    multibyte_at_limit = "é" * 512
    assert len(multibyte_at_limit) == 512, (
        f"test setup error: expected a 512-character key, got {len(multibyte_at_limit)}"
    )
    assert len(multibyte_at_limit.encode("utf-8")) == 1024, (
        f"test setup error: expected a 1024-byte key, got {len(multibyte_at_limit.encode('utf-8'))}"
    )
    s3.put_object(Bucket=bucket, Key=multibyte_at_limit, Body=b"multibyte-at-limit")
    got = s3.get_object(Bucket=bucket, Key=multibyte_at_limit)["Body"].read()
    assert got == b"multibyte-at-limit", (
        f"512-char/1024-byte key did not round-trip its body, got {got!r}"
    )

    # --- Break exactly one thing: one byte over the limit.
    over_limit = "a" * 1025
    exc = _client_error(lambda: s3.put_object(Bucket=bucket, Key=over_limit, Body=b"over-limit"))
    assert exc is not None, "PutObject with a 1025-byte key was accepted; the 1024-byte contract limit is not enforced"
    code = exc.response.get("Error", {}).get("Code")
    message = exc.response.get("Error", {}).get("Message")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "KeyTooLongError", f"expected KeyTooLongError for a 1025-byte key, got {code!r}"
    assert message == KEY_TOO_LONG_MESSAGE, f"unexpected KeyTooLongError message: {message!r}"
    assert status == 400, f"expected HTTP 400 for KeyTooLongError, got {status!r}"

    # --- Effect absent: the rejected put created nothing.
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=over_limit))
    assert exc is not None, "the rejected 1025-byte key is readable via HeadObject; the write was not rolled back"
    listed_after = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert over_limit not in listed_after, "the rejected 1025-byte key appears in ListObjectsV2"
    assert listed_after == {at_limit, multibyte_at_limit}, (
        f"bucket contents changed unexpectedly: {sorted(len(k) for k in listed_after)}"
    )

    # --- Byte-counted, not char-counted: 513 two-byte characters == 1026 bytes == too long,
    # even though it is only 513 characters.
    multibyte_over = "é" * 513
    assert len(multibyte_over) == 513 and len(multibyte_over.encode("utf-8")) == 1026, (
        f"test setup error: expected a 513-character/1026-byte key, got "
        f"{len(multibyte_over)} chars / {len(multibyte_over.encode('utf-8'))} bytes"
    )
    exc = _client_error(lambda: s3.put_object(Bucket=bucket, Key=multibyte_over, Body=b"x"))
    assert exc is not None, (
        "a 513-character / 1026-BYTE key was accepted; the emulator is counting characters, "
        "not UTF-8 bytes"
    )
    code = exc.response.get("Error", {}).get("Code")
    message = exc.response.get("Error", {}).get("Message")
    assert code == "KeyTooLongError", (
        f"expected KeyTooLongError for a 1026-byte (513-char) key, got {code!r}"
    )
    assert message == KEY_TOO_LONG_MESSAGE, f"unexpected KeyTooLongError message: {message!r}"

    # --- Control still works: the at-limit object is untouched by the rejections.
    final = s3.get_object(Bucket=bucket, Key=at_limit)["Body"].read()
    assert final == b"at-limit", f"the at-limit object was altered by the rejected puts, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
