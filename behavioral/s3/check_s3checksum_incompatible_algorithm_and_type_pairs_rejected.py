"""s3checksum-incompatible-algorithm-and-type-pairs-rejected."""

from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-incompatible-algorithm-and-type-pairs-rejected"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

# Kept small because CRC32C is computed in pure Python; a one-part multipart upload has no 5 MiB
# floor, so the positive control is still a real completion.
_PAYLOAD = b"one-part-multipart-body-whose-full-object-crc32c-is-checked-" * 64


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


def _abort_upload(s3, bucket, key, upload_id):
    """Best-effort abort of a possibly-already-completed multipart upload (teardown only)."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


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
    """The base64 big-endian CRC-32C (Castagnoli) of ``data``, as S3 puts in ChecksumCRC32C."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ byte) & 0xFF]
    crc ^= 0xFFFFFFFF
    return base64.b64encode(crc.to_bytes(4, "big")).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """SHA256+FULL_OBJECT and CRC64NVME+COMPOSITE multipart uploads are refused with InvalidRequest.

    Neither refusal opens an upload; SHA256+COMPOSITE is accepted, and CRC32C+FULL_OBJECT completes
    with a whole-object CRC32C matching a locally computed Castagnoli digest.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # --- Refusal 1: SHA256 has no whole-object form.
    sha_full = _client_error(
        lambda: s3.create_multipart_upload(
            Bucket=bucket, Key="sha256-full-object", ChecksumAlgorithm="SHA256",
            ChecksumType="FULL_OBJECT",
        )
    )
    assert sha_full is not None, (
        "CreateMultipartUpload accepted ChecksumAlgorithm=SHA256 with ChecksumType=FULL_OBJECT; "
        "SHA-256 cannot be combined across parts, so there is no whole-object form to produce"
    )
    sha_code = sha_full.response.get("Error", {}).get("Code")
    sha_status = sha_full.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert sha_code == "InvalidRequest", (
        f"expected InvalidRequest for SHA256 + FULL_OBJECT, got {sha_code!r}"
    )
    assert sha_status == 400, f"expected HTTP 400, got {sha_status!r}"
    sha_message = sha_full.response.get("Error", {}).get("Message")
    assert sha_message == (
        "The FULL_OBJECT checksum type cannot be used with the sha256 checksum algorithm."
    ), f"the SHA256 + FULL_OBJECT refusal's message is {sha_message!r}"

    # --- Refusal 2: CRC64NVME has no composite form.
    crc64_composite = _client_error(
        lambda: s3.create_multipart_upload(
            Bucket=bucket, Key="crc64nvme-composite", ChecksumAlgorithm="CRC64NVME",
            ChecksumType="COMPOSITE",
        )
    )
    assert crc64_composite is not None, (
        "CreateMultipartUpload accepted ChecksumAlgorithm=CRC64NVME with ChecksumType=COMPOSITE; "
        "CRC64NVME is composable, so AWS offers only its whole-object form"
    )
    crc64_code = crc64_composite.response.get("Error", {}).get("Code")
    crc64_status = crc64_composite.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert crc64_code == "InvalidRequest", (
        f"expected InvalidRequest for CRC64NVME + COMPOSITE, got {crc64_code!r}"
    )
    assert crc64_status == 400, f"expected HTTP 400, got {crc64_status!r}"
    crc64_message = crc64_composite.response.get("Error", {}).get("Message")
    assert crc64_message == (
        "The COMPOSITE checksum type cannot be used with the crc64nvme checksum algorithm."
    ), f"the CRC64NVME + COMPOSITE refusal's message is {crc64_message!r}"

    # --- Effect absent: neither refusal created an upload to leak or complete.
    open_uploads = []
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        open_uploads += [u["Key"] for u in page.get("Uploads", [])]
    assert open_uploads == [], (
        f"the two refused CreateMultipartUpload calls left {open_uploads!r} open; a refusal must "
        "not mint an upload id"
    )

    # --- POSITIVE CONTROL A: the legal composite pair for the same algorithm that was refused.
    legal_sha = s3.create_multipart_upload(
        Bucket=bucket, Key="sha256-composite", ChecksumAlgorithm="SHA256",
        ChecksumType="COMPOSITE",
    )
    sha_upload_id = legal_sha["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, "sha256-composite", sha_upload_id))
    assert legal_sha.get("ChecksumType") == "COMPOSITE", (
        f"the legal SHA256 pair reported ChecksumType {legal_sha.get('ChecksumType')!r}"
    )
    assert legal_sha.get("ChecksumAlgorithm") == "SHA256", (
        f"the legal SHA256 pair reported ChecksumAlgorithm "
        f"{legal_sha.get('ChecksumAlgorithm')!r}"
    )

    # --- POSITIVE CONTROL B: the legal whole-object pair, carried through to a real object.
    want = _crc32c_b64(_PAYLOAD)
    legal_crc = s3.create_multipart_upload(
        Bucket=bucket, Key="crc32c-full-object", ChecksumAlgorithm="CRC32C",
        ChecksumType="FULL_OBJECT",
    )
    crc_upload_id = legal_crc["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, "crc32c-full-object", crc_upload_id))
    assert legal_crc.get("ChecksumType") == "FULL_OBJECT", (
        f"the legal CRC32C pair reported ChecksumType {legal_crc.get('ChecksumType')!r}"
    )
    uploaded = s3.upload_part(
        Bucket=bucket, Key="crc32c-full-object", UploadId=crc_upload_id, PartNumber=1,
        Body=_PAYLOAD, ChecksumAlgorithm="CRC32C", ChecksumCRC32C=want,
    )
    assert uploaded["ChecksumCRC32C"] == want, (
        f"UploadPart reported {uploaded['ChecksumCRC32C']!r}, the client computed {want!r} from "
        f"the Castagnoli polynomial over the same {len(_PAYLOAD)} bytes"
    )
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key="crc32c-full-object", UploadId=crc_upload_id,
        MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": uploaded["ETag"],
             "ChecksumCRC32C": uploaded["ChecksumCRC32C"]},
        ]},
        ChecksumType="FULL_OBJECT", ChecksumCRC32C=want, MpuObjectSize=len(_PAYLOAD),
    )
    assert done["ChecksumType"] == "FULL_OBJECT", (
        f"the completion reported ChecksumType {done.get('ChecksumType')!r}, want 'FULL_OBJECT'"
    )
    assert done["ChecksumCRC32C"] == want, (
        f"the completion reported {done['ChecksumCRC32C']!r}; a FULL_OBJECT CRC32C over these "
        f"bytes is {want!r}"
    )
    assert "-" not in done["ChecksumCRC32C"], (
        f"a FULL_OBJECT checksum carries no part-count suffix; got {done['ChecksumCRC32C']!r}"
    )
    got = s3.get_object(Bucket=bucket, Key="crc32c-full-object", ChecksumMode="ENABLED")
    body = got["Body"].read()
    assert body == _PAYLOAD, (
        f"the completed object is {len(body)} bytes, want {len(_PAYLOAD)}"
    )
    assert got["ChecksumCRC32C"] == want == _crc32c_b64(body), (
        f"GetObject reported {got['ChecksumCRC32C']!r}; the bytes it returned checksum to "
        f"{_crc32c_b64(body)!r} and the client computed {want!r} before uploading them"
    )
    assert got["ChecksumType"] == "FULL_OBJECT", (
        f"GetObject reported ChecksumType {got.get('ChecksumType')!r}, want 'FULL_OBJECT'"
    )
    # Only the legal upload produced an object; the refused pairs produced none.
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys += [o["Key"] for o in page.get("Contents", [])]
    assert keys == ["crc32c-full-object"], (
        f"the bucket holds {keys!r}; only the completed legal upload may have produced an object"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
