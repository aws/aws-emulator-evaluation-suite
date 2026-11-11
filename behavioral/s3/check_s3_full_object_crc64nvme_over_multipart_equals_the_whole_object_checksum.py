"""s3-full-object-crc64nvme-over-multipart-equals-the-whole-object-checksum."""

from __future__ import annotations

import base64
import os
import zlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-full-object-crc64nvme-over-multipart-equals-the-whole-object-checksum"
GROUP = 'checksum-semantics'
SERVICES = ['s3']

_PART = 5 * 1024 * 1024      # 5 MiB — the minimum size for a non-final part
_NPARTS = 3
_TOTAL = _PART * _NPARTS


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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort_upload(s3, bucket, key, upload_id):
    """Best-effort abort of a possibly-already-completed multipart upload (teardown only)."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


# CRC-64/NVME: poly 0xAD93D23594C93659 reflected, init/xorout all-ones, refin/refout. The table
# constant below is bit-reverse(poly). awscrt computes it natively when installed.
_CRC64_POLY_REFLECTED = 0x9A6C9329AC4BC9B5
_CRC64_TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ (_CRC64_POLY_REFLECTED if _crc & 1 else 0)
    _CRC64_TABLE.append(_crc)

try:
    from awscrt.checksums import crc64nvme as _crt_crc64nvme
except ImportError:  # pragma: no cover - the pure-Python table above is the fallback
    _crt_crc64nvme = None


def _crc64nvme(data: bytes) -> int:
    """The CRC-64/NVME of ``data`` as an integer."""
    if _crt_crc64nvme is not None:
        return _crt_crc64nvme(data)
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = _CRC64_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


def _gf2_times(mat: list[int], vec: int) -> int:
    out, i = 0, 0
    while vec:
        if vec & 1:
            out ^= mat[i]
        vec >>= 1
        i += 1
    return out


def _gf2_square(mat: list[int]) -> list[int]:
    return [_gf2_times(mat, m) for m in mat]


def _crc64nvme_combine(crc1: int, crc2: int, len2: int) -> int:
    """The CRC-64/NVME of A+B from crc(A), crc(B) and len(B), as zlib's crc32_combine."""
    if len2 == 0:
        return crc1
    odd = [_CRC64_POLY_REFLECTED] + [1 << n for n in range(63)]
    even = _gf2_square(odd)
    odd = _gf2_square(even)
    while True:
        even = _gf2_square(odd)
        if len2 & 1:
            crc1 = _gf2_times(even, crc1)
        len2 >>= 1
        if not len2:
            break
        odd = _gf2_square(even)
        if len2 & 1:
            crc1 = _gf2_times(odd, crc1)
        len2 >>= 1
        if not len2:
            break
    return crc1 ^ crc2


def _crc64_b64(crc: int) -> str:
    """A CRC-64/NVME integer in the base64 form S3 puts in ChecksumCRC64NVME."""
    return base64.b64encode(crc.to_bytes(8, "big")).decode()


def _crc32_b64(data: bytes) -> str:
    """The base64 big-endian CRC32 of ``data``, in the form S3 puts in ChecksumCRC32."""
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FULL_OBJECT multipart checksum (CRC64NVME and CRC32) equals the checksum of the assembled
    bytes, while COMPOSITE over the same parts is the CRC32 of the part digests suffixed "-3".

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    parts = [os.urandom(_PART) for _ in range(_NPARTS)]
    whole = b"".join(parts)
    assert len(whole) == _TOTAL, f"payload is {len(whole)} bytes, expected {_TOTAL}"

    # Each part is hashed once; the whole-object CRC64 is combined from the part CRCs.
    part_crc64 = [_crc64nvme(p) for p in parts]
    whole_crc64 = part_crc64[0]
    for crc, p in zip(part_crc64[1:], parts[1:], strict=True):
        whole_crc64 = _crc64nvme_combine(whole_crc64, crc, len(p))
    want_crc64 = _crc64_b64(whole_crc64)
    want_crc32 = _crc32_b64(whole)
    # COMPOSITE is defined as the checksum of the concatenated RAW part digests, then "-N".
    want_composite = _crc32_b64(
        b"".join(zlib.crc32(p).to_bytes(4, "big") for p in parts)
    ) + f"-{_NPARTS}"

    def _upload(key, algorithm, checksum_type, complete_kwargs):
        """Upload the same three parts under one (algorithm, ChecksumType) pair."""
        created = s3.create_multipart_upload(
            Bucket=bucket, Key=key, ChecksumAlgorithm=algorithm, ChecksumType=checksum_type
        )
        upload_id = created["UploadId"]
        # Registered before any assertion: an open upload keeps billing for its parts.
        ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))
        assert created.get("ChecksumType") == checksum_type, (
            f"CreateMultipartUpload echoed ChecksumType {created.get('ChecksumType')!r}, "
            f"asked for {checksum_type!r}"
        )
        field = "ChecksumCRC64NVME" if algorithm == "CRC64NVME" else "ChecksumCRC32"
        manifest = []
        for number, chunk in enumerate(parts, 1):
            # Supplied explicitly: botocore computes CRC64NVME only with awscrt installed.
            # S3 still verifies the bytes against the value sent.
            part_checksum = (
                _crc64_b64(part_crc64[number - 1]) if algorithm == "CRC64NVME"
                else _crc32_b64(chunk)
            )
            uploaded = s3.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number,
                Body=chunk, ChecksumAlgorithm=algorithm, **{field: part_checksum},
            )
            assert uploaded[field] == part_checksum, (
                f"UploadPart echoed {field} {uploaded[field]!r} for part {number}; the "
                f"client sent {part_checksum!r}"
            )
            manifest.append(
                {"ETag": uploaded["ETag"], "PartNumber": number, field: uploaded[field]}
            )
        completed = s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={"Parts": manifest}, **complete_kwargs
        )
        return field, completed

    # Leg 1: FULL_OBJECT / CRC64NVME.
    field64, full64 = _upload(
        "mpu-fullobject-crc64.bin", "CRC64NVME", "FULL_OBJECT",
        {"ChecksumType": "FULL_OBJECT", "ChecksumCRC64NVME": want_crc64,
         "MpuObjectSize": _TOTAL},
    )
    assert full64["ChecksumType"] == "FULL_OBJECT", (
        f"a FULL_OBJECT completion reported ChecksumType {full64['ChecksumType']!r}"
    )
    assert "-" not in full64[field64], (
        f"a FULL_OBJECT checksum carried a part suffix: {full64[field64]!r} — that is the "
        "COMPOSITE form, so the whole-object mode was not actually honoured"
    )
    assert full64[field64] == want_crc64, (
        f"S3 returned CRC64NVME {full64[field64]!r} for the assembled object; the client "
        f"computed {want_crc64!r} over the same {_TOTAL} bytes"
    )

    # The stored checksum must survive a read, not just be echoed by the write.
    got64 = s3.get_object(Bucket=bucket, Key="mpu-fullobject-crc64.bin", ChecksumMode="ENABLED")
    assert got64["ChecksumCRC64NVME"] == want_crc64, (
        f"GetObject reported CRC64NVME {got64['ChecksumCRC64NVME']!r}, want {want_crc64!r}"
    )
    assert got64["ChecksumType"] == "FULL_OBJECT", (
        f"GetObject reported ChecksumType {got64['ChecksumType']!r}, want 'FULL_OBJECT'"
    )
    assert got64["Body"].read() == whole, "the assembled object's bytes are not the three parts"

    # HeadObject without PartNumber returns no PartsCount, so the count is read here.
    attrs64 = s3.get_object_attributes(
        Bucket=bucket, Key="mpu-fullobject-crc64.bin",
        ObjectAttributes=["Checksum", "ObjectParts", "ObjectSize"],
    )
    assert attrs64["ObjectParts"]["TotalPartsCount"] == _NPARTS, (
        f"GetObjectAttributes reported {attrs64['ObjectParts'].get('TotalPartsCount')!r} parts, "
        f"want {_NPARTS} — the part boundaries were flattened by the completion"
    )
    assert attrs64["ObjectSize"] == _TOTAL, (
        f"GetObjectAttributes reported ObjectSize {attrs64['ObjectSize']!r}, want {_TOTAL}"
    )

    # Leg 2: FULL_OBJECT / CRC32. CRC64NVME cannot be COMPOSITE (CreateMultipartUpload fails
    # InvalidRequest), so the two modes are compared under CRC32.
    field32, full32 = _upload(
        "mpu-fullobject-crc32.bin", "CRC32", "FULL_OBJECT",
        {"ChecksumType": "FULL_OBJECT", "ChecksumCRC32": want_crc32,
         "MpuObjectSize": _TOTAL},
    )
    assert full32["ChecksumType"] == "FULL_OBJECT", (
        f"a FULL_OBJECT completion reported ChecksumType {full32['ChecksumType']!r}"
    )
    assert full32[field32] == want_crc32, (
        f"S3 returned CRC32 {full32[field32]!r} for the assembled object; the client computed "
        f"{want_crc32!r} over the same bytes"
    )
    assert "-" not in full32[field32], (
        f"a FULL_OBJECT CRC32 carried a part suffix: {full32[field32]!r}"
    )

    # Leg 3: COMPOSITE / CRC32 over the identical parts.
    _, composite = _upload("mpu-composite-crc32.bin", "CRC32", "COMPOSITE", {})
    assert composite["ChecksumType"] == "COMPOSITE", (
        f"a COMPOSITE completion reported ChecksumType {composite['ChecksumType']!r}"
    )
    assert composite["ChecksumCRC32"] == want_composite, (
        f"S3 returned COMPOSITE CRC32 {composite['ChecksumCRC32']!r}; the client computed "
        f"{want_composite!r} as crc32(concat of the three raw part digests) + '-{_NPARTS}'"
    )
    assert composite["ChecksumCRC32"] != want_crc32, (
        f"the COMPOSITE checksum equalled the whole-object one ({want_crc32!r}) — the two "
        "modes are not distinguished, so ChecksumType is being ignored"
    )

    # GetObject carries the "-N" suffix; GetObjectAttributes carries the bare digest.
    got_comp = s3.get_object(Bucket=bucket, Key="mpu-composite-crc32.bin", ChecksumMode="ENABLED")
    assert got_comp["ChecksumCRC32"] == want_composite, (
        f"GetObject reported COMPOSITE CRC32 {got_comp['ChecksumCRC32']!r}, want {want_composite!r}"
    )
    assert got_comp["Body"].read() == whole, (
        "the COMPOSITE object's bytes are not the three parts — the checksum mode changed the data"
    )
    attrs_comp = s3.get_object_attributes(
        Bucket=bucket, Key="mpu-composite-crc32.bin", ObjectAttributes=["Checksum", "ObjectParts"],
    )
    assert attrs_comp["Checksum"]["ChecksumCRC32"] == want_composite.rsplit("-", 1)[0], (
        f"GetObjectAttributes reported {attrs_comp['Checksum']['ChecksumCRC32']!r}; it returns "
        f"the COMPOSITE digest WITHOUT the '-{_NPARTS}' suffix, want "
        f"{want_composite.rsplit('-', 1)[0]!r}"
    )
    per_part = {p["PartNumber"]: p["ChecksumCRC32"] for p in attrs_comp["ObjectParts"]["Parts"]}
    expected_per_part = {i: _crc32_b64(p) for i, p in enumerate(parts, 1)}
    assert per_part == expected_per_part, (
        f"the per-part CRC32s S3 stored are {per_part!r}; the client computed "
        f"{expected_per_part!r}"
    )

    for label, resp in (("FULL_OBJECT/CRC64NVME", full64), ("FULL_OBJECT/CRC32", full32),
                        ("COMPOSITE/CRC32", composite)):
        assert resp["ETag"].strip('"').endswith(f"-{_NPARTS}"), (
            f"{label} produced ETag {resp['ETag']!r}, which is not part-count suffixed — a "
            "completed multipart object's ETag is never a plain MD5"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
