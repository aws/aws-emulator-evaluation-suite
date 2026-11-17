"""crc32-multipart-default-composite-vs-full-object-checksum."""

from __future__ import annotations

import base64
import hashlib
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crc32-multipart-default-composite-vs-full-object-checksum"
GROUP = "checksum-semantics"
SERVICES = ["s3"]

_PART1 = 5 * 1024 * 1024  # the multipart minimum for a non-final part
_PART2 = 1024 * 1024


def _delete_bucket(client, bucket):
    """Abort open uploads, delete every object, then the bucket."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
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


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-crcty-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a LocationConstraint for
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort_upload(s3, bucket, key, upload_id):
    """Abort a possibly-already-completed multipart upload (teardown); only not-found is tolerated."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _crc32_b64(data: bytes) -> str:
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CRC32 multipart upload with no ChecksumType defaults to COMPOSITE, whose ETag and
    ChecksumCRC32 are built from the parts' own digests; FULL_OBJECT over identical bytes
    instead reports the plain CRC32 of the assembled object, under the same part-suffixed ETag.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    part1 = bytes((i * 5 + 2) % 251 for i in range(_PART1))
    part2 = bytes((i * 13 + 7) % 251 for i in range(_PART2))
    whole = part1 + part2

    part_crcs = [_crc32_b64(part1), _crc32_b64(part2)]
    want_composite_crc32 = _crc32_b64(
        zlib.crc32(part1).to_bytes(4, "big") + zlib.crc32(part2).to_bytes(4, "big")
    ) + "-2"
    want_full_object_crc32 = _crc32_b64(whole)
    want_etag = f'"{hashlib.md5(hashlib.md5(part1).digest() + hashlib.md5(part2).digest()).hexdigest()}-2"'

    def _upload(key, create_kwargs, complete_kwargs):
        created = s3.create_multipart_upload(Bucket=bucket, Key=key, **create_kwargs)
        upload_id = created["UploadId"]
        ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))
        manifest = []
        for number, chunk, crc in ((1, part1, part_crcs[0]), (2, part2, part_crcs[1])):
            uploaded = s3.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number,
                Body=chunk, ChecksumAlgorithm="CRC32", ChecksumCRC32=crc,
            )
            manifest.append(
                {"ETag": uploaded["ETag"], "PartNumber": number, "ChecksumCRC32": uploaded["ChecksumCRC32"]}
            )
        return created, s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": manifest},
            **complete_kwargs,
        )

    # Leg 1: no ChecksumType anywhere — the SDK's own CRC32 default is COMPOSITE.
    created_a, completed_a = _upload("default-checksum-type.bin", {"ChecksumAlgorithm": "CRC32"}, {})
    assert created_a.get("ChecksumType") == "COMPOSITE", (
        f"CreateMultipartUpload with ChecksumAlgorithm CRC32 and no ChecksumType echoed "
        f"ChecksumType {created_a.get('ChecksumType')!r}; want 'COMPOSITE'"
    )
    assert completed_a["ETag"] == want_etag, (
        f"the default-ChecksumType completion returned ETag {completed_a['ETag']!r}; want "
        f"{want_etag!r} (md5 of the two parts' own md5 digests, suffixed '-2')"
    )
    assert completed_a["ChecksumCRC32"] == want_composite_crc32, (
        f"the default-ChecksumType completion returned ChecksumCRC32 {completed_a['ChecksumCRC32']!r}; "
        f"want {want_composite_crc32!r} (crc32 of the two parts' own crc32 digests, suffixed '-2')"
    )

    head_a = s3.head_object(Bucket=bucket, Key="default-checksum-type.bin", ChecksumMode="ENABLED")
    assert head_a.get("ChecksumType") == "COMPOSITE", (
        f"HeadObject on the default-ChecksumType object reported ChecksumType "
        f"{head_a.get('ChecksumType')!r}; want 'COMPOSITE'"
    )
    assert head_a["ETag"] == want_etag, (
        f"HeadObject on the default-ChecksumType object reported ETag {head_a['ETag']!r}; want "
        f"{want_etag!r}"
    )
    assert head_a.get("ChecksumCRC32") == want_composite_crc32, (
        f"HeadObject on the default-ChecksumType object reported ChecksumCRC32 "
        f"{head_a.get('ChecksumCRC32')!r}; want {want_composite_crc32!r}"
    )

    attrs_a = s3.get_object_attributes(
        Bucket=bucket, Key="default-checksum-type.bin", ObjectAttributes=["ObjectParts"]
    )
    per_part_a = {p["PartNumber"]: p["ChecksumCRC32"] for p in attrs_a["ObjectParts"]["Parts"]}
    assert per_part_a == {1: part_crcs[0], 2: part_crcs[1]}, (
        f"GetObjectAttributes ObjectParts carried per-part CRC32s {per_part_a!r}; want "
        f"{{1: {part_crcs[0]!r}, 2: {part_crcs[1]!r}}}, the digests of the uploaded bytes"
    )

    # Leg 2: identical bytes, ChecksumType pinned to FULL_OBJECT throughout.
    _, completed_b = _upload(
        "full-object-checksum-type.bin",
        {"ChecksumAlgorithm": "CRC32", "ChecksumType": "FULL_OBJECT"},
        {"ChecksumType": "FULL_OBJECT", "ChecksumCRC32": want_full_object_crc32, "MpuObjectSize": len(whole)},
    )
    assert completed_b["ChecksumType"] == "FULL_OBJECT", (
        f"the FULL_OBJECT completion reported ChecksumType {completed_b['ChecksumType']!r}; "
        "want 'FULL_OBJECT'"
    )
    assert completed_b["ChecksumCRC32"] == want_full_object_crc32, (
        f"the FULL_OBJECT completion returned ChecksumCRC32 {completed_b['ChecksumCRC32']!r}; "
        f"want {want_full_object_crc32!r} (the plain crc32 of the assembled bytes)"
    )
    assert completed_b["ETag"] == want_etag, (
        f"the FULL_OBJECT completion returned ETag {completed_b['ETag']!r}; want the same "
        f"{want_etag!r} as the COMPOSITE completion of the identical parts — ETag does not "
        "depend on ChecksumType"
    )

    head_b = s3.head_object(Bucket=bucket, Key="full-object-checksum-type.bin", ChecksumMode="ENABLED")
    assert head_b.get("ChecksumType") == "FULL_OBJECT", (
        f"HeadObject on the FULL_OBJECT object reported ChecksumType {head_b.get('ChecksumType')!r}; "
        "want 'FULL_OBJECT'"
    )
    assert head_b.get("ChecksumCRC32") == want_full_object_crc32, (
        f"HeadObject on the FULL_OBJECT object reported ChecksumCRC32 "
        f"{head_b.get('ChecksumCRC32')!r}; want {want_full_object_crc32!r}, with no part suffix"
    )
    assert head_b["ETag"] == want_etag, (
        f"HeadObject on the FULL_OBJECT object reported ETag {head_b['ETag']!r}; want {want_etag!r}"
    )

    assert head_a.get("ChecksumCRC32") != head_b.get("ChecksumCRC32"), (
        f"the COMPOSITE and FULL_OBJECT checksums of the identical bytes were both "
        f"{head_a.get('ChecksumCRC32')!r} — the two modes are not actually distinguished"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
