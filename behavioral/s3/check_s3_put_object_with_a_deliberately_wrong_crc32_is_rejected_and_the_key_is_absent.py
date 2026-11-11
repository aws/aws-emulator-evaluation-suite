"""s3-put-object-with-a-deliberately-wrong-crc32-is-rejected-and-the-key-is-absent."""

from __future__ import annotations

import base64
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-put-object-with-a-deliberately-wrong-crc32-is-rejected-and-the-key-is-absent"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

_PAYLOAD = b"the-bytes-whose-checksum-s3-must-recompute-rather-than-store" * 64


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
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _crc32_b64(data: bytes) -> str:
    """The base64 big-endian CRC32 of ``data``, in the form S3 puts in ChecksumCRC32."""
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A supplied CRC32 is recomputed over the body, not stored; a mismatch is BadDigest.

    The key stays absent, and the stored checksum equals a client-side zlib CRC32 of the bytes.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "checksum-verified.bin"

    correct = _crc32_b64(_PAYLOAD)
    wrong = _crc32_b64(_PAYLOAD + b"x")
    assert wrong != correct, "the wrong digest collided with the correct one"
    assert len(base64.b64decode(wrong)) == 4, (
        f"the wrong digest must still be a well-formed 4-byte CRC32, got "
        f"{len(base64.b64decode(wrong))} bytes"
    )

    # A well-formed CRC32 of a payload one byte longer: only server recomputation can refuse it.
    exc = _client_error(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD, ChecksumCRC32=wrong)
    )
    assert exc is not None, (
        f"PutObject accepted ChecksumCRC32={wrong!r} for a body whose actual CRC32 is "
        f"{correct!r} — the header is being stored rather than verified, so every corrupted "
        "upload on the target is silently accepted"
    )
    code = exc.response.get("Error", {}).get("Code")
    message = exc.response.get("Error", {}).get("Message")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert (code, message) == (
        "BadDigest",
        "The CRC32 you specified did not match the calculated checksum.",
    ), f"expected BadDigest with the CRC32 mismatch message, got {(code, message)!r}"
    assert status == 400, f"expected HTTP 400 for BadDigest, got {status!r}"

    # --- Effect absent: nothing was stored at the key.
    missing = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert missing is not None, "the rejected PutObject stored the object anyway"
    assert missing.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"HeadObject after the refusal returned "
        f"{missing.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )
    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [o["Key"] for o in page.get("Contents", [])]
    assert listed == [], f"the bucket holds {listed!r} after the refused PUT; it must be empty"

    # --- POSITIVE CONTROL: the identical bytes with the correct zlib-computed CRC32.
    stored = s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD, ChecksumCRC32=correct)
    assert stored["ChecksumCRC32"] == correct, (
        f"the accepted PutObject echoed {stored['ChecksumCRC32']!r}, the client computed {correct!r}"
    )
    assert stored["ChecksumType"] == "FULL_OBJECT", (
        f"a single-part PutObject checksum is a whole-object one; got ChecksumType "
        f"{stored.get('ChecksumType')!r}"
    )

    # --- And the VALUE survives a read, compared to the client computation, not to itself.
    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert got["ChecksumCRC32"] == correct, (
        f"GetObject with ChecksumMode=ENABLED returned {got['ChecksumCRC32']!r}; the client "
        f"computed {correct!r} with zlib.crc32 over the same {len(_PAYLOAD)} bytes"
    )
    body = got["Body"].read()
    assert body == _PAYLOAD, (
        f"the stored object is {len(body)} bytes, want {len(_PAYLOAD)}"
    )
    assert _crc32_b64(body) == got["ChecksumCRC32"], (
        f"the bytes S3 returned checksum to {_crc32_b64(body)!r} but S3 reported "
        f"{got['ChecksumCRC32']!r} for them"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
