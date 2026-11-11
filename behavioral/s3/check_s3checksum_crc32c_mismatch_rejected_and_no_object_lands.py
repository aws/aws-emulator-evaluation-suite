"""s3checksum-crc32c-mismatch-rejected-and-no-object-lands."""

from __future__ import annotations

import base64
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-crc32c-mismatch-rejected-and-no-object-lands"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

# Small enough that the pure-Python CRC32C below costs milliseconds, large enough that a
# single flipped byte cannot be hidden by a trivial digest.
_PAYLOAD = b"crc32c-is-recomputed-by-the-service-not-echoed-back-" * 128


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), then delete it."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(
                    Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
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


_CRC32C_POLY = 0x82F63B78
_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_CRC32C_POLY if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def _crc32c_b64(data: bytes) -> str:
    """The base64 big-endian CRC-32C (Castagnoli) of ``data``, as S3 puts in ChecksumCRC32C.

    Computed here from the polynomial rather than taken from any AWS library, so the value the
    assertions compare against is genuinely independent of the SDK and of the service.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ byte) & 0xFF]
    crc ^= 0xFFFFFFFF
    return base64.b64encode(crc.to_bytes(4, "big")).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with a well-formed but wrong ChecksumCRC32C is refused with 400 BadDigest and its exact
    message and leaves the key absent (HeadObject 404, empty listing), while the same PutObject with the
    correct value stores a ChecksumCRC32C equal to a locally computed CRC-32C."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "crc32c-verified.bin"

    correct = _crc32c_b64(_PAYLOAD)
    wrong = _crc32c_b64(_PAYLOAD + b"x")
    assert wrong != correct, "the wrong digest collided with the correct one; pick other bytes"
    assert len(base64.b64decode(wrong)) == 4, (
        f"the wrong digest must still be a well-formed 4-byte CRC32C, got "
        f"{len(base64.b64decode(wrong))} bytes"
    )
    # A CRC32C that is NOT the zlib CRC32 of the same bytes: an emulator that implements
    # ChecksumCRC32C with zlib.crc32 would accept a value this check never sends.
    zlib_crc32 = base64.b64encode(zlib.crc32(_PAYLOAD).to_bytes(4, "big")).decode()
    assert correct != zlib_crc32, (
        f"the payload's CRC32C {correct!r} equals its CRC32 {zlib_crc32!r}; the two polynomials "
        "must disagree for this check to distinguish them"
    )

    # --- Break exactly one thing: the checksum, over otherwise valid bytes.
    exc = _client_error(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD, ChecksumCRC32C=wrong)
    )
    assert exc is not None, (
        f"PutObject accepted ChecksumCRC32C={wrong!r} for a body whose actual CRC32C is "
        f"{correct!r} — the header is being stored rather than verified, so every corrupted "
        "upload is silently accepted"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "BadDigest", f"expected BadDigest for a mismatched CRC32C, got {code!r}"
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The CRC32C you specified did not match the calculated checksum.", (
        f"expected the exact BadDigest message for a mismatched CRC32C, got {message!r}"
    )
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

    # --- POSITIVE CONTROL: the identical bytes with the correct CRC32C.
    stored = s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD, ChecksumCRC32C=correct)
    assert stored["ChecksumCRC32C"] == correct, (
        f"the accepted PutObject echoed {stored['ChecksumCRC32C']!r}, the client computed "
        f"{correct!r} from the Castagnoli polynomial over the same {len(_PAYLOAD)} bytes"
    )
    assert stored["ChecksumType"] == "FULL_OBJECT", (
        f"a single-part PutObject checksum is a whole-object one; got ChecksumType "
        f"{stored.get('ChecksumType')!r}"
    )

    # --- And the VALUE survives both read paths, compared to the client computation.
    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert got["ChecksumCRC32C"] == correct, (
        f"GetObject with ChecksumMode=ENABLED returned {got['ChecksumCRC32C']!r}; the client "
        f"computed {correct!r} over the same {len(_PAYLOAD)} bytes"
    )
    body = got["Body"].read()
    assert body == _PAYLOAD, f"the stored object is {len(body)} bytes, want {len(_PAYLOAD)}"
    assert _crc32c_b64(body) == got["ChecksumCRC32C"], (
        f"the bytes S3 returned checksum to {_crc32c_b64(body)!r} but S3 reported "
        f"{got['ChecksumCRC32C']!r} for them"
    )
    head = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert head["ChecksumCRC32C"] == correct, (
        f"HeadObject with ChecksumMode=ENABLED returned {head.get('ChecksumCRC32C')!r}, "
        f"want {correct!r}"
    )
    assert head["ChecksumType"] == "FULL_OBJECT", (
        f"HeadObject reported ChecksumType {head.get('ChecksumType')!r}, want 'FULL_OBJECT'"
    )
    # ChecksumMode is opt-in: without it the digest is withheld, which is how a client knows it
    # has to ask. An emulator that always returns it is over-permissive in the response shape.
    quiet = s3.head_object(Bucket=bucket, Key=key)
    assert "ChecksumCRC32C" not in quiet, (
        f"HeadObject without ChecksumMode=ENABLED returned ChecksumCRC32C="
        f"{quiet.get('ChecksumCRC32C')!r}; the digest must be withheld unless asked for"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
