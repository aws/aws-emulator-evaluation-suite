"""multipart-complete-checksum-type-mismatched-from-create-rejected."""

from __future__ import annotations

import base64
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multipart-complete-checksum-type-mismatched-from-create-rejected"
GROUP = "checksum-rejection"
SERVICES = ["s3"]

_PAYLOAD = b"full-object-vs-composite-checksum-type-mismatch-body-" * 2048


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
    name = ctx.unique_name("sim2real-behav-mpuctm-")
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_MISMATCH = (
    "InvalidRequest",
    "The upload was created using the FULL_OBJECT checksum mode. The complete request must use "
    "the same checksum mode.",
)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload with ChecksumType COMPOSITE on an upload created with CRC32 +
    FULL_OBJECT is rejected, and completing it with the matching FULL_OBJECT type still succeeds.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "mismatched-checksum-type.bin"

    created = s3.create_multipart_upload(
        Bucket=bucket, Key=key, ChecksumAlgorithm="CRC32", ChecksumType="FULL_OBJECT"
    )
    upload_id = created["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))

    part_crc = _crc32_b64(_PAYLOAD)
    uploaded = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1,
        Body=_PAYLOAD, ChecksumAlgorithm="CRC32", ChecksumCRC32=part_crc,
    )
    manifest = [{"ETag": uploaded["ETag"], "PartNumber": 1, "ChecksumCRC32": uploaded["ChecksumCRC32"]}]

    code, message = _error(
        lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": manifest},
            ChecksumType="COMPOSITE",
        )
    )
    assert (code, message) == _MISMATCH, (
        f"completing with ChecksumType COMPOSITE against a FULL_OBJECT upload gave "
        f"({code!r}, {message!r}); want {_MISMATCH!r}"
    )

    # Effect absent: the refused completion left no object.
    listed = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
              for o in page.get("Contents", [])]
    assert listed == [], (
        f"the rejected CompleteMultipartUpload left an object behind: {listed!r}"
    )

    # Positive control: the same upload, the same parts, completed with the matching type.
    want_whole = _crc32_b64(_PAYLOAD)
    completed = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": manifest},
        ChecksumType="FULL_OBJECT", ChecksumCRC32=want_whole, MpuObjectSize=len(_PAYLOAD),
    )
    assert completed["ChecksumType"] == "FULL_OBJECT", (
        f"the matching completion reported ChecksumType {completed['ChecksumType']!r}"
    )
    assert completed["ChecksumCRC32"] == want_whole, (
        f"the matching completion reported ChecksumCRC32 {completed['ChecksumCRC32']!r}; want "
        f"{want_whole!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert head["ChecksumType"] == "FULL_OBJECT" and head["ChecksumCRC32"] == want_whole, (
        f"HeadObject reported ({head['ChecksumType']!r}, {head['ChecksumCRC32']!r}); want "
        f"('FULL_OBJECT', {want_whole!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
