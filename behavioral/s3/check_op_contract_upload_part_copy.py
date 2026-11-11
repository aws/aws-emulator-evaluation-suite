"""op-contract-uploadPartCopy."""
from __future__ import annotations

import os

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-uploadPartCopy"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of an upload id that is not in progress, as real S3 returns it.
_NO_SUCH_UPLOAD = ("NoSuchUpload", "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")

_MIN_PART_SIZE = 5 * 1024 * 1024  # 5 MiB - minimum size for a non-final multipart part


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadPartCopy: success-path contract (copied part is byte-accurate and
    assembles correctly via CompleteMultipartUpload) plus a NoSuchUpload error
    boundary for a copy against a nonexistent/aborted upload id."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    # --- set up a source object big enough to serve as a valid non-final part ---
    source_key = "source-object"
    source_body = os.urandom(_MIN_PART_SIZE) + b"source-tail-marker"
    s3.put_object(Bucket=bucket, Key=source_key, Body=source_body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=source_key))

    dest_key = "dest-object"
    copy_source = f"{bucket}/{source_key}"

    # === success path ===
    create_resp = s3.create_multipart_upload(Bucket=bucket, Key=dest_key)
    upload_id = create_resp["UploadId"]
    ctx.on_cleanup(
        lambda: _abort_quietly(s3, bucket, dest_key, upload_id)
    )

    # Part 1: copy the first MIN_PART_SIZE bytes from the source via UploadPartCopy.
    copy_range = f"bytes=0-{_MIN_PART_SIZE - 1}"
    part1 = s3.upload_part_copy(
        Bucket=bucket,
        Key=dest_key,
        UploadId=upload_id,
        PartNumber=1,
        CopySource=copy_source,
        CopySourceRange=copy_range,
    )
    result = part1["CopyPartResult"]
    assert "ETag" in result and result["ETag"], "CopyPartResult missing ETag"
    assert "LastModified" in result, "CopyPartResult missing LastModified"
    part1_etag = result["ETag"]

    # Part 2: a small final part uploaded directly (covers the tail marker bytes).
    tail_bytes = source_body[_MIN_PART_SIZE:]
    part2 = s3.upload_part(
        Bucket=bucket, Key=dest_key, UploadId=upload_id, PartNumber=2, Body=tail_bytes
    )
    part2_etag = part2["ETag"]

    complete = s3.complete_multipart_upload(
        Bucket=bucket,
        Key=dest_key,
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"ETag": part1_etag, "PartNumber": 1},
                {"ETag": part2_etag, "PartNumber": 2},
            ]
        },
    )
    assert complete.get("Key") == dest_key, (
        f"CompleteMultipartUpload response Key mismatch: expected {dest_key!r}, "
        f"got {complete.get('Key')!r}"
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=dest_key))

    # Assert the assembled object is byte-for-byte identical to the source.
    fetched = s3.get_object(Bucket=bucket, Key=dest_key)["Body"].read()
    assert fetched == source_body, (
        f"assembled object ({len(fetched)} bytes) does not match source "
        f"({len(source_body)} bytes) after UploadPartCopy + UploadPart + Complete"
    )

    # ListParts on a now-completed upload should fail (upload id retired).
    code = _error(
        lambda: s3.list_parts(Bucket=bucket, Key=dest_key, UploadId=upload_id)
    )
    assert code == _NO_SUCH_UPLOAD, f"expected NoSuchUpload after completion, got {code}"

    # === error boundary: UploadPartCopy against a bogus/nonexistent UploadId ===
    bogus_upload_id = "bogus-upload-id-does-not-exist-00000000000000000000000000000000"
    code = _error(
        lambda: s3.upload_part_copy(
            Bucket=bucket,
            Key=dest_key,
            UploadId=bogus_upload_id,
            PartNumber=1,
            CopySource=copy_source,
            CopySourceRange=copy_range,
        )
    )
    assert code == _NO_SUCH_UPLOAD, f"expected NoSuchUpload for bogus upload id, got {code}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-uploadpartcopy-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    return name


def _delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for upload in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(
                Bucket=name, Key=upload["Key"], UploadId=upload["UploadId"]
            )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _abort_quietly(s3, bucket: str, key: str, upload_id: str) -> None:
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
