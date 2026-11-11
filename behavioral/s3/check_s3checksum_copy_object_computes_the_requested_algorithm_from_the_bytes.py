"""s3checksum-copy-object-computes-the-requested-algorithm-from-the-bytes."""

from __future__ import annotations

import base64
import hashlib
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-copy-object-computes-the-requested-algorithm-from-the-bytes"
GROUP = 'checksum-semantics'
SERVICES = ['s3']

# Kept small: the CRC32C below is computed here in pure Python, from the polynomial.
_PAYLOAD = b"the-copy-must-be-hashed-server-side-with-an-algorithm-the-source-never-had-" * 48


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


def _sha256_b64(data: bytes) -> str:
    """The base64 SHA-256 of ``data``, in the form S3 puts in ChecksumSHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


_CRC32C_POLY = 0x82F63B78
_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_CRC32C_POLY if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def _crc32c_b64(data: bytes) -> str:
    """The base64 big-endian CRC-32C (Castagnoli) of ``data``, as S3 puts in ChecksumCRC32C."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ byte) & 0xFF]
    crc ^= 0xFFFFFFFF
    return base64.b64encode(crc.to_bytes(4, "big")).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject with ChecksumAlgorithm=SHA256 from a source holding only a CRC32C returns the SHA-256
    of the bytes and stores it on the destination, a copy with no algorithm carries the source's CRC32C,
    and the source is unchanged."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    want_crc32c = _crc32c_b64(_PAYLOAD)
    want_sha256 = _sha256_b64(_PAYLOAD)

    # --- The source: CRC32C only, so no SHA-256 exists anywhere to be forwarded.
    source = s3.put_object(Bucket=bucket, Key="src.bin", Body=_PAYLOAD,
                           ChecksumCRC32C=want_crc32c)
    assert source["ChecksumCRC32C"] == want_crc32c, (
        f"PutObject echoed {source['ChecksumCRC32C']!r}, the client computed {want_crc32c!r} from "
        f"the Castagnoli polynomial over the same {len(_PAYLOAD)} bytes"
    )
    src_head = s3.head_object(Bucket=bucket, Key="src.bin", ChecksumMode="ENABLED")
    assert "ChecksumSHA256" not in src_head, (
        f"the source object already reports ChecksumSHA256={src_head.get('ChecksumSHA256')!r}; "
        "this check requires a source with no SHA-256, so that the copy has nothing to echo"
    )
    assert src_head["ChecksumCRC32C"] == want_crc32c, (
        f"the source reports ChecksumCRC32C={src_head.get('ChecksumCRC32C')!r}, want "
        f"{want_crc32c!r}"
    )

    # --- The copy asks for an algorithm the source never had.
    copied = s3.copy_object(
        Bucket=bucket, Key="dst-sha256.bin",
        CopySource={"Bucket": bucket, "Key": "src.bin"},
        ChecksumAlgorithm="SHA256",
    )
    result = copied["CopyObjectResult"]
    assert result.get("ChecksumSHA256") == want_sha256, (
        f"CopyObject reported ChecksumSHA256={result.get('ChecksumSHA256')!r}; the client computed "
        f"{want_sha256!r} with hashlib over the source's {len(_PAYLOAD)} bytes. The source carries "
        f"only CRC32C {want_crc32c!r}, so this value can only come from hashing the data"
    )
    assert result.get("ChecksumType") == "FULL_OBJECT", (
        f"a single-part copy's checksum is a whole-object one; got ChecksumType "
        f"{result.get('ChecksumType')!r}"
    )

    # --- Read the destination back, both bytes and digest.
    dst = s3.get_object(Bucket=bucket, Key="dst-sha256.bin", ChecksumMode="ENABLED")
    dst_body = dst["Body"].read()
    assert dst_body == _PAYLOAD, (
        f"the copy is {len(dst_body)} bytes, want {len(_PAYLOAD)}; a checksum over the wrong bytes "
        "is worse than none"
    )
    assert dst["ChecksumSHA256"] == want_sha256, (
        f"GetObject on the copy reported {dst['ChecksumSHA256']!r}, want {want_sha256!r}"
    )
    assert _sha256_b64(dst_body) == dst["ChecksumSHA256"], (
        f"the bytes S3 returned hash to {_sha256_b64(dst_body)!r} but S3 reported "
        f"{dst['ChecksumSHA256']!r} for them"
    )
    assert "ChecksumCRC32C" not in dst, (
        f"the copy reports ChecksumCRC32C={dst.get('ChecksumCRC32C')!r} as well; requesting SHA256 "
        "replaces the algorithm rather than accumulating the source's"
    )
    dst_attrs = s3.get_object_attributes(
        Bucket=bucket, Key="dst-sha256.bin", ObjectAttributes=["Checksum", "ObjectSize"],
    )
    assert dst_attrs["Checksum"]["ChecksumSHA256"] == want_sha256, (
        f"GetObjectAttributes on the copy reported "
        f"{dst_attrs['Checksum'].get('ChecksumSHA256')!r}, want {want_sha256!r}"
    )
    assert dst_attrs["ObjectSize"] == len(_PAYLOAD), (
        f"GetObjectAttributes reported ObjectSize {dst_attrs['ObjectSize']}, want {len(_PAYLOAD)}"
    )

    # --- The source is untouched: the copy computed a digest, it did not migrate one.
    src_after = s3.head_object(Bucket=bucket, Key="src.bin", ChecksumMode="ENABLED")
    assert src_after["ChecksumCRC32C"] == want_crc32c, (
        f"the source now reports ChecksumCRC32C={src_after.get('ChecksumCRC32C')!r}, want "
        f"{want_crc32c!r}"
    )
    assert "ChecksumSHA256" not in src_after, (
        f"the copy gave the SOURCE a ChecksumSHA256={src_after.get('ChecksumSHA256')!r}"
    )

    # --- Control on the other branch: a copy that names NO algorithm carries CRC32C forward.
    plain = s3.copy_object(
        Bucket=bucket, Key="dst-default.bin",
        CopySource={"Bucket": bucket, "Key": "src.bin"},
    )
    plain_result = plain["CopyObjectResult"]
    assert plain_result.get("ChecksumCRC32C") == want_crc32c, (
        f"a copy with no ChecksumAlgorithm reported "
        f"{plain_result.get('ChecksumCRC32C')!r}; it must preserve the source's CRC32C "
        f"{want_crc32c!r}"
    )
    plain_head = s3.head_object(Bucket=bucket, Key="dst-default.bin", ChecksumMode="ENABLED")
    assert plain_head["ChecksumCRC32C"] == want_crc32c, (
        f"the preserved copy reports {plain_head.get('ChecksumCRC32C')!r}, want {want_crc32c!r}"
    )
    assert "ChecksumSHA256" not in plain_head, (
        f"the preserved copy invented a ChecksumSHA256={plain_head.get('ChecksumSHA256')!r}; only "
        "the copy that ASKED for SHA256 may have one"
    )
    # And the CRC32C really is the Castagnoli digest of the bytes, not zlib's CRC32 of them.
    zlib_crc32 = base64.b64encode(zlib.crc32(_PAYLOAD).to_bytes(4, "big")).decode()
    assert plain_head["ChecksumCRC32C"] != zlib_crc32, (
        f"the preserved CRC32C equals zlib.crc32 of the same bytes ({zlib_crc32!r}); CRC32C uses "
        "the Castagnoli polynomial and the two must differ"
    )

    # --- A copy of a key that does not exist must not produce a digest of anything.
    absent = _client_error(
        lambda: s3.copy_object(
            Bucket=bucket, Key="dst-nothing.bin",
            CopySource={"Bucket": bucket, "Key": "no-such-src.bin"},
            ChecksumAlgorithm="SHA256",
        )
    )
    assert absent is not None, "CopyObject succeeded from a source key that was never created"
    absent_code = absent.response.get("Error", {}).get("Code")
    assert absent_code == "NoSuchKey", (
        f"expected NoSuchKey copying from a missing source, got {absent_code!r}"
    )
    absent_message = absent.response.get("Error", {}).get("Message")
    assert absent_message == "The specified key does not exist.", (
        f"the missing-source refusal's message is {absent_message!r}, want "
        "'The specified key does not exist.'"
    )
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys += [o["Key"] for o in page.get("Contents", [])]
    assert sorted(keys) == ["dst-default.bin", "dst-sha256.bin", "src.bin"], (
        f"the bucket holds {sorted(keys)!r}; the failed copy must have created nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
