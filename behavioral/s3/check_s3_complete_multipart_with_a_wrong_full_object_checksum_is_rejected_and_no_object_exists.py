"""s3-complete-multipart-with-a-wrong-full-object-checksum-is-rejected-and-no-object-exists."""

from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-complete-multipart-with-a-wrong-full-object-checksum-is-rejected-and-no-object-exists"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

_PART_A = 5 * 1024 * 1024      # 5 MiB — the minimum size for a non-final part
_PART_B = 1 * 1024 * 1024      # 1 MiB — final part, may be smaller
_TOTAL = _PART_A + _PART_B


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


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


# Stdlib CRC-64/NVME so the check needs no awscrt dependency.
# CRC-64/NVME: poly 0xAD93D23594C93659 reflected, init/xorout all-ones, refin/refout.
_CRC64_TABLE = []
for _byte in range(256):
    _crc = _byte
    for _ in range(8):
        _crc = (_crc >> 1) ^ (0x9A6C9329AC4BC9B5 if _crc & 1 else 0)
    _CRC64_TABLE.append(_crc)


def _crc64nvme_b64(data: bytes) -> str:
    """The base64 CRC-64/NVME of ``data``, in the form S3 puts in ChecksumCRC64NVME."""
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = _CRC64_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return base64.b64encode((crc ^ 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A wrong whole-object CRC64NVME on CompleteMultipartUpload is a 400 BadDigest: no object
    exists, the upload id stays listed, and the same upload then completes with the right checksum.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "wrong-full-object-checksum.bin"

    part_a = os.urandom(_PART_A)
    part_b = os.urandom(_PART_B)
    whole = part_a + part_b
    correct = _crc64nvme_b64(whole)
    # A syntactically valid, correctly-sized CRC64NVME of DIFFERENT bytes: the request is
    # well-formed, so only a server-side recomputation over the assembled object can refuse it.
    wrong = _crc64nvme_b64(b"a deliberately different payload for the wrong digest")
    assert wrong != correct, "the wrong digest collided with the correct one; pick other bytes"

    created = s3.create_multipart_upload(
        Bucket=bucket, Key=key, ChecksumAlgorithm="CRC64NVME", ChecksumType="FULL_OBJECT"
    )
    upload_id = created["UploadId"]
    # Registered before any assertion: an orphaned multipart upload bills for its stored parts.
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))

    manifest = []
    for number, chunk in ((1, part_a), (2, part_b)):
        uploaded = s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number, Body=chunk,
            ChecksumAlgorithm="CRC64NVME",
        )
        assert uploaded["ChecksumCRC64NVME"] == _crc64nvme_b64(chunk), (
            f"UploadPart {number} reported CRC64NVME {uploaded['ChecksumCRC64NVME']!r}, the "
            f"client computed {_crc64nvme_b64(chunk)!r} over the same {len(chunk)} bytes"
        )
        manifest.append({
            "ETag": uploaded["ETag"], "PartNumber": number,
            "ChecksumCRC64NVME": uploaded["ChecksumCRC64NVME"],
        })

    exc = _client_error(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": manifest},
        ChecksumType="FULL_OBJECT", ChecksumCRC64NVME=wrong, MpuObjectSize=_TOTAL,
    ))
    assert exc is not None, (
        f"CompleteMultipartUpload accepted a whole-object CRC64NVME of {wrong!r} for an object "
        f"whose actual checksum is {correct!r} — the supplied checksum is being stored rather "
        "than verified, which is the over-permissive failure this check exists to catch"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "BadDigest", f"expected BadDigest for a mismatched whole-object checksum, got {code!r}"
    message = exc.response.get("Error", {}).get("Message")
    want = "The crc64nvme you specified did not match the calculated checksum."
    assert message == want, f"expected {want!r} for a mismatched whole-object checksum, got {message!r}"
    assert status == 400, f"expected HTTP 400 for BadDigest, got {status!r}"

    missing = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert missing is not None, (
        "the rejected completion created an object at the key — the checksum failure did not "
        "prevent the assembly"
    )
    assert missing.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"HeadObject after the refusal returned "
        f"{missing.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )
    listed_keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed_keys += [o["Key"] for o in page.get("Contents", [])]
    assert listed_keys == [], (
        f"the bucket holds {listed_keys!r} after the refused completion; it must be empty"
    )

    # A rejected completion is a no-op on the upload, not an implicit abort.
    listed_upload_ids = []
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        listed_upload_ids += [u["UploadId"] for u in page.get("Uploads", [])]
    assert upload_id in listed_upload_ids, (
        f"the upload id vanished from ListMultipartUploads after the BadDigest refusal; listed "
        f"{[u[:16] for u in listed_upload_ids]!r}. Real AWS leaves it open and completable — an "
        "emulator that aborts it on a checksum failure destroys the customer's uploaded parts"
    )

    # Positive control: same upload id and parts, so the checksum is the only variable.
    completed = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": manifest},
        ChecksumType="FULL_OBJECT", ChecksumCRC64NVME=correct, MpuObjectSize=_TOTAL,
    )
    assert completed["ChecksumCRC64NVME"] == correct, (
        f"the control completion reported {completed['ChecksumCRC64NVME']!r}, want {correct!r}"
    )
    assert completed["ChecksumType"] == "FULL_OBJECT", (
        f"the control completion reported ChecksumType {completed['ChecksumType']!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    body = got["Body"].read()
    assert body == whole, (
        f"the control object is {len(body)} bytes, want {_TOTAL} — the parts were not assembled "
        "in order"
    )
    assert got["ChecksumCRC64NVME"] == correct, (
        f"GetObject reported {got['ChecksumCRC64NVME']!r} for the control object, want {correct!r}"
    )

    after = []
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        after += [u["UploadId"] for u in page.get("Uploads", [])]
    assert upload_id not in after, (
        f"the upload id is still listed after a SUCCESSFUL completion: {[u[:16] for u in after]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
