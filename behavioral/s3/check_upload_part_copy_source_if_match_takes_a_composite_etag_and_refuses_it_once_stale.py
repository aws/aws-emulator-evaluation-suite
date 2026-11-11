"""upload-part-copy-source-if-match-takes-a-composite-etag-and-refuses-it-once-stale."""

from __future__ import annotations

import hashlib
import os
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-part-copy-source-if-match-takes-a-composite-etag-and-refuses-it-once-stale"
GROUP = "conditional"
SERVICES = ["s3"]

PART = 5 * 1024 * 1024
PRECONDITION = ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold")


def _delete_bucket(client, bucket):
    """Empty a bucket (uploads, objects, versions, delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _refusal(fn):
    """(Error.Code, Error.Message, HTTP status) of the ClientError ``fn`` raises; FAILS on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"the call SUCCEEDED where real AWS refuses it: {result!r}")


def _abort(s3, bucket, key, upload):
    """Abort ``upload``; one already completed or aborted is gone, anything else raises."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchUpload", "NoSuchBucket"):
            raise


def _multipart_etag(parts):
    """The ETag S3 gives a multipart object: MD5 of the parts' binary MD5s, then '-<count>'."""
    digest = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest()
    return f'"{digest}-{len(parts)}"'


def _start(ctx, s3, bucket, key):
    upload = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload))
    return upload


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadPartCopy with CopySourceIfMatch accepts a multipart source's composite ETag and copies
    exactly the addressed byte range; once the source is overwritten, the same ETag is refused 412
    PreconditionFailed and adds no part to the destination upload.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    src, dst = "source/large.bin", "copies/large.bin"

    parts = [os.urandom(PART), os.urandom(PART + secrets.randbelow(2048))]
    upload = _start(ctx, s3, bucket, src)
    done = []
    for number, body in enumerate(parts, start=1):
        etag = s3.upload_part(Bucket=bucket, Key=src, UploadId=upload, PartNumber=number, Body=body)["ETag"]
        done.append({"PartNumber": number, "ETag": etag})
    composite = s3.complete_multipart_upload(
        Bucket=bucket, Key=src, UploadId=upload, MultipartUpload={"Parts": done}
    )["ETag"]
    assert composite == _multipart_etag(parts), f"source ETag {composite!r}, expected {_multipart_etag(parts)!r}"
    whole = b"".join(parts)

    # Copy a range spanning the source's part boundary, conditioned on its composite ETag.
    start = PART - 1 - secrets.randbelow(PART // 2)
    # PART + 1 bytes starting just below the 5 MiB boundary, so the range spans both source parts.
    end = start + PART
    copy_upload = _start(ctx, s3, bucket, dst)
    copied = s3.upload_part_copy(
        Bucket=bucket, Key=dst, UploadId=copy_upload, PartNumber=1,
        CopySource={"Bucket": bucket, "Key": src}, CopySourceRange=f"bytes={start}-{end}",
        CopySourceIfMatch=composite,
    )["CopyPartResult"]["ETag"]
    want_part = whole[start:end + 1]
    assert copied == f'"{hashlib.md5(want_part).hexdigest()}"', (
        f"UploadPartCopy part ETag {copied!r} is not the MD5 of source bytes {start}-{end}"
    )

    # Overwrite the source: its composite ETag is stale, and the conditional copy is refused.
    s3.put_object(Bucket=bucket, Key=src, Body=b"replaced-source")
    late = _refusal(lambda: s3.upload_part_copy(
        Bucket=bucket, Key=dst, UploadId=copy_upload, PartNumber=2,
        CopySource={"Bucket": bucket, "Key": src}, CopySourceIfMatch=composite,
    ))
    want = (*PRECONDITION, 412)
    assert late == want, f"UploadPartCopy on a stale composite ETag: expected {want!r}, got {late!r}"
    listed = s3.list_parts(Bucket=bucket, Key=dst, UploadId=copy_upload).get("Parts", [])
    got = [(p["PartNumber"], p["Size"], p["ETag"]) for p in listed]
    assert got == [(1, len(want_part), copied)], f"after the refusal ListParts reports {got!r}"

    final = s3.complete_multipart_upload(
        Bucket=bucket, Key=dst, UploadId=copy_upload,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": copied}]},
    )
    assert final["ETag"] == _multipart_etag([want_part]), (
        f"copy ETag {final['ETag']!r}, expected {_multipart_etag([want_part])!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=dst)["Body"].read()
    assert body == want_part, (
        f"the copied object holds {len(body)} bytes (md5 {hashlib.md5(body).hexdigest()}), expected source "
        f"bytes {start}-{end}: {len(want_part)} bytes (md5 {hashlib.md5(want_part).hexdigest()})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
