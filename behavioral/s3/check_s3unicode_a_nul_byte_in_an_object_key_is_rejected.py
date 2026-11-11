"""s3unicode-a-nul-byte-in-an-object-key-is-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-a-nul-byte-in-an-object-key-is-rejected"
GROUP = 'errors'
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A NUL byte in an object key is refused with a bare HTTP 400 and no S3 error code, and no object is
    created, while the neighbouring C0 control U+0001 in the same position is stored, readable and
    listed: NUL is the one C0 control S3 refuses.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    prefix = "nul/"
    key_soh = f"{prefix}a\x01b.txt"   # U+0001: accepted
    key_nul = f"{prefix}a\x00b.txt"   # U+0000: refused
    body = b"c0-control-payload\x00\xff"

    # --- Positive control: the adjacent C0 control is a legal key character.
    s3.put_object(Bucket=bucket, Key=key_soh, Body=body)
    got = s3.get_object(Bucket=bucket, Key=key_soh)["Body"].read()
    assert got == body, (
        f"the U+0001 key did not round-trip its body: sent {body!r}, got {got!r}"
    )
    listed = _list_keys(s3, bucket, prefix)
    assert listed == [key_soh], (
        f"ListObjectsV2 did not return exactly the U+0001 key: expected [{key_soh!r}], got "
        f"{listed!r}"
    )
    assert listed[0].encode("utf-8") == key_soh.encode("utf-8"), (
        f"the listed U+0001 key's bytes differ from the written key's: listed "
        f"{listed[0].encode('utf-8')!r}, written {key_soh.encode('utf-8')!r}"
    )

    # --- Break exactly one thing: the same key with U+0000 instead of U+0001.
    assert key_nul.replace("\x00", "\x01") == key_soh, (
        f"test setup error: {key_nul!r} and {key_soh!r} differ in more than the one byte"
    )
    exc = _client_error(lambda: s3.put_object(Bucket=bucket, Key=key_nul, Body=body))
    assert exc is not None, (
        f"PutObject accepted a key containing a NUL byte ({key_nul!r}); real S3 refuses it"
    )
    status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 400, f"expected HTTP 400 for a NUL byte in the key, got {status!r}"
    code = exc.response.get("Error", {}).get("Code")
    assert code == "400", (
        f"expected the errorless-400 stand-in code '400' for a NUL byte in the key, got {code!r} -- "
        f"real S3 returns no modelled S3 error code here"
    )

    # --- Effect absent: nothing was created, and the key is not even addressable.
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_nul))
    assert exc is not None, (
        f"the NUL-byte key {key_nul!r} is readable via HeadObject; the refused write landed anyway"
    )
    assert _list_keys(s3, bucket, prefix) == [key_soh], (
        f"after the refused NUL-byte write the prefix should still hold exactly {key_soh!r}, got "
        f"{_list_keys(s3, bucket, prefix)!r}"
    )

    # --- Positive control still holds: the refusal did not disturb the U+0001 object.
    final = s3.get_object(Bucket=bucket, Key=key_soh)["Body"].read()
    assert final == body, (
        f"the U+0001 object was altered by the refused NUL-byte write: expected {body!r}, got "
        f"{final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
