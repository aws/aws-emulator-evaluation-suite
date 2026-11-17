"""copy-object-defaults-to-the-composite-sources-sha256-as-a-full-object-digest."""
from __future__ import annotations

import base64
import hashlib
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-defaults-to-the-composite-sources-sha256-as-a-full-object-digest"
GROUP = "copy-checksum-inheritance"
SERVICES = ["s3"]

_LEAD = 5 * 1024 * 1024  # S3's floor for a non-final multipart part
_TAIL = 768 * 1024
_NOT_FOUND = ("NoSuchBucket", "NoSuchKey", "NoSuchUpload")


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """CopyObject of a two-part SHA256 COMPOSITE multipart source, given no ChecksumAlgorithm of
    its own, keeps SHA256 but hashes the destination as one FULL_OBJECT digest over the assembled
    bytes, with a fresh, unsuffixed MD5 ETag; the source keeps its own composite digest."""
    s3 = ctx.client("s3")
    bucket = _fresh_bucket(ctx, s3)

    lead = os.urandom(_LEAD)
    tail = os.urandom(_TAIL)
    whole = lead + tail

    upload = s3.create_multipart_upload(Bucket=bucket, Key="source", ChecksumAlgorithm="SHA256")
    upload_id = upload["UploadId"]
    ctx.on_cleanup(lambda: _abort_if_open(s3, bucket, "source", upload_id))

    completed_parts = []
    for number, piece in ((1, lead), (2, tail)):
        put = s3.upload_part(
            Bucket=bucket, Key="source", UploadId=upload_id, PartNumber=number, Body=piece,
            ChecksumAlgorithm="SHA256",
        )
        completed_parts.append(
            {"PartNumber": number, "ETag": put["ETag"], "ChecksumSHA256": put["ChecksumSHA256"]}
        )
    source = s3.complete_multipart_upload(
        Bucket=bucket, Key="source", UploadId=upload_id,
        MultipartUpload={"Parts": completed_parts},
    )
    assert source.get("ChecksumType") == "COMPOSITE", (
        f"completing a 2-part SHA256 multipart upload must report ChecksumType 'COMPOSITE', got "
        f"{source.get('ChecksumType')!r}"
    )
    source_etag = source["ETag"]
    assert source_etag.strip('"').endswith("-2"), (
        f"a composite 2-part ETag carries the '-2' part-count suffix; got {source_etag!r}"
    )

    # --- The copy names no ChecksumAlgorithm at all.
    copy = s3.copy_object(Bucket=bucket, Key="copy", CopySource={"Bucket": bucket, "Key": "source"})
    outcome = copy["CopyObjectResult"]
    want_sha256 = _sha256_b64(whole)
    want_etag = f'"{hashlib.md5(whole).hexdigest()}"'

    assert outcome.get("ChecksumType") == "FULL_OBJECT", (
        f"an unqualified copy of a composite source must report ChecksumType 'FULL_OBJECT', got "
        f"{outcome.get('ChecksumType')!r} — the destination has no parts to be composite over"
    )
    assert outcome.get("ChecksumSHA256") == want_sha256, (
        f"CopyObjectResult.ChecksumSHA256 is {outcome.get('ChecksumSHA256')!r}; hashing the "
        f"{len(whole)} assembled bytes with SHA-256 gives {want_sha256!r}"
    )
    assert outcome.get("ETag") == want_etag, (
        f"CopyObjectResult.ETag is {outcome.get('ETag')!r}; expected the plain MD5 {want_etag!r} "
        "with no part-count suffix"
    )
    assert outcome.get("ETag") != source_etag, (
        f"the copy's ETag {outcome.get('ETag')!r} must not equal the source's suffixed ETag "
        f"{source_etag!r}: a FULL_OBJECT copy mints its own representation"
    )

    # --- The write survives a read, under both digest-bearing operations.
    copy_head = s3.head_object(Bucket=bucket, Key="copy", ChecksumMode="ENABLED")
    assert (copy_head.get("ChecksumType"), copy_head.get("ChecksumSHA256"), copy_head.get("ETag")) \
        == ("FULL_OBJECT", want_sha256, want_etag), (
        f"HeadObject on the copy reported "
        f"({copy_head.get('ChecksumType')!r}, {copy_head.get('ChecksumSHA256')!r}, "
        f"{copy_head.get('ETag')!r}); want ('FULL_OBJECT', {want_sha256!r}, {want_etag!r})"
    )
    copy_attrs = s3.get_object_attributes(
        Bucket=bucket, Key="copy", ObjectAttributes=["Checksum", "ObjectParts", "ObjectSize"]
    )
    assert copy_attrs.get("Checksum") == {"ChecksumSHA256": want_sha256, "ChecksumType": "FULL_OBJECT"}, (
        f"GetObjectAttributes on the copy reported {copy_attrs.get('Checksum')!r}; want the "
        f"whole-object SHA-256 {want_sha256!r} under ChecksumType 'FULL_OBJECT'"
    )
    assert "ObjectParts" not in copy_attrs, (
        f"the copy reported ObjectParts {copy_attrs.get('ObjectParts')!r}; a FULL_OBJECT copy has "
        "no parts to enumerate"
    )
    assert copy_attrs.get("ObjectSize") == len(whole), (
        f"GetObjectAttributes reported ObjectSize {copy_attrs.get('ObjectSize')!r}, want "
        f"{len(whole)}"
    )
    copy_body = s3.get_object(Bucket=bucket, Key="copy")["Body"].read()
    assert copy_body == whole, "the copy's bytes differ from the multipart source's assembled bytes"

    # --- The copy leaves the source object unchanged.
    source_after = s3.head_object(Bucket=bucket, Key="source", ChecksumMode="ENABLED")
    assert (source_after.get("ChecksumType"), source_after.get("ETag")) == ("COMPOSITE", source_etag), (
        f"the source changed after being copied FROM: "
        f"({source_after.get('ChecksumType')!r}, {source_after.get('ETag')!r}), want "
        f"('COMPOSITE', {source_etag!r})"
    )


# ===== helpers =====
def _fresh_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-behav-cpdf-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, name))
    return name


def _empty_and_delete(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _NOT_FOUND:
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _abort_if_open(s3, bucket, key, upload_id) -> None:
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _NOT_FOUND:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
