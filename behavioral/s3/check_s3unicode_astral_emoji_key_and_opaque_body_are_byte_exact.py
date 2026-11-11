"""s3unicode-astral-emoji-key-and-opaque-body-are-byte-exact."""

from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-astral-emoji-key-and-opaque-body-are-byte-exact"
GROUP = 'representation'
SERVICES = ['s3']


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
    return name


def _list_keys(s3, bucket, prefix):
    """Every key under ``prefix``, across all pages."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None
# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key holding U+1F600 and a body holding invalid UTF-8 survive Put, Get, Head and ListObjectsV2
    byte for byte, the ETag matching the local MD5; the mojibake (latin-1 re-decoded) key is a 404,
    since S3 stores keys as UTF-8 bytes and bodies as opaque octets.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    emoji = "\U0001f600"  # GRINNING FACE: 4 bytes in UTF-8, a surrogate pair in UTF-16
    prefix = "uni/"
    key = f"{prefix}{emoji}-café-日本語.bin"
    body = b"\xff\xfe\x00\x01" + emoji.encode("utf-8") + b"\xc3\x28" + b"\r\n"

    # --- Setup assertions: the inputs really are the awkward shapes this check is about.
    assert len(emoji.encode("utf-8")) == 4, (
        f"test setup error: expected a 4-byte UTF-8 character, got "
        f"{len(emoji.encode('utf-8'))} bytes for {emoji!r}"
    )
    assert emoji.encode("utf-16-be") == b"\xd8\x3d\xde\x00", (
        f"test setup error: expected the surrogate pair D83D DE00, got "
        f"{emoji.encode('utf-16-be')!r}"
    )
    decode_failed = None
    try:
        body.decode("utf-8")
    except UnicodeDecodeError as exc:
        decode_failed = exc
    assert decode_failed is not None, (
        f"test setup error: the body was meant to be invalid UTF-8 but decoded cleanly: {body!r}"
    )

    # --- Store it once. Everything after this is a read.
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- GetObject returns the exact octets, and the server-side digest agrees with ours.
    got = s3.get_object(Bucket=bucket, Key=key)
    payload = got["Body"].read()
    assert payload == body, (
        f"GetObject did not return the body byte-for-byte: sent {body!r}, got {payload!r}"
    )
    assert got["ContentLength"] == len(body), (
        f"ContentLength disagrees with the stored bytes: header says {got['ContentLength']!r}, "
        f"the body is {len(body)} bytes"
    )
    assert got["ETag"].strip('"') == hashlib.md5(body).hexdigest(), (
        f"the server-computed ETag is not the MD5 of the bytes we sent: ETag "
        f"{got['ETag']!r}, md5 {hashlib.md5(body).hexdigest()!r} -- the content was altered in "
        f"transit or at rest"
    )

    # --- HeadObject agrees with GetObject about the same astral-plane key.
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == len(body), (
        f"HeadObject reports {head['ContentLength']!r} bytes for a {len(body)}-byte object"
    )
    assert head["ETag"] == got["ETag"], (
        f"HeadObject and GetObject disagree on the ETag of one key: "
        f"{head['ETag']!r} vs {got['ETag']!r}"
    )

    # --- ListObjectsV2 returns the key with identical codepoints AND identical UTF-8 bytes.
    listed = _list_keys(s3, bucket, prefix)
    assert listed == [key], (
        f"ListObjectsV2 did not return exactly the one key written under {prefix!r}: "
        f"expected [{key!r}], got {listed!r}"
    )
    assert listed[0].encode("utf-8") == key.encode("utf-8"), (
        f"the listed key's UTF-8 bytes differ from the written key's: "
        f"listed {listed[0].encode('utf-8')!r}, written {key.encode('utf-8')!r}"
    )

    # --- Effect absent: the double-decoded (mojibake) spelling of the same key does not exist.
    mojibake = key.encode("utf-8").decode("latin-1")
    assert mojibake != key, (
        f"test setup error: the mojibake spelling is identical to the key, so this arm proves "
        f"nothing: {key!r}"
    )
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=mojibake))
    assert exc is not None, (
        f"the latin-1 mojibake spelling {mojibake!r} of the key resolves to an object; the key was "
        f"stored double-decoded"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the mojibake key, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert _list_keys(s3, bucket, prefix) == [key], (
        f"the bucket gained or lost a key while probing the mojibake spelling: "
        f"{_list_keys(s3, bucket, prefix)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
