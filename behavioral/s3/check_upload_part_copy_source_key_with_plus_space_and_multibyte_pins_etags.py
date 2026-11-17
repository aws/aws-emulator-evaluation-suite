"""upload-part-copy-source-key-with-plus-space-and-multibyte-pins-etags."""

from __future__ import annotations

import hashlib
import os

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "upload-part-copy-source-key-with-plus-space-and-multibyte-pins-etags"
GROUP = "multipart"
SERVICES = ["s3"]

_PART1_SIZE = 5 * 1024 * 1024
_PART2_SIZE = 4096

_NO_SUCH_KEY = ("NoSuchKey", "The specified key does not exist.")


def _error(fn):
    """The (code, message) of the ClientError fn() raises; raises if fn() SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _quoted_md5(data: bytes) -> str:
    return f'"{hashlib.md5(data).hexdigest()}"'


def _composite_etag(part_etags, n: int) -> str:
    digests = b"".join(bytes.fromhex(e.strip('"')) for e in part_etags)
    return f'"{hashlib.md5(digests).hexdigest()}-{n}"'


def _abort_quietly(s3, bucket: str, key: str, upload_id: str) -> None:
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _drop_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            stale = ([{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
                     + [{"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])])
            if stale:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": stale})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-behav-pluscopy-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _drop_bucket(s3, name))
    return name


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """UploadPartCopy on a multibyte-plus-space source key pins each part's ETag and the
    completed ETag to their MD5 composite; spelling the plus as a space in CopySource is
    refused NoSuchKey with no part recorded, and the correctly spelled key still completes.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    src_key = "docs/café menu+specials.bin"
    body = os.urandom(_PART1_SIZE + _PART2_SIZE)
    s3.put_object(Bucket=bucket, Key=src_key, Body=body)

    part1_expected = _quoted_md5(body[:_PART1_SIZE])
    part2_expected = _quoted_md5(body[_PART1_SIZE:])

    # === success path: two ranges of the real key assemble into a new multipart object ===
    dest_key = "dest/assembled.bin"
    create = s3.create_multipart_upload(Bucket=bucket, Key=dest_key)
    upload_id = create["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, dest_key, upload_id))

    part1 = s3.upload_part_copy(
        Bucket=bucket, Key=dest_key, UploadId=upload_id, PartNumber=1,
        CopySource={"Bucket": bucket, "Key": src_key},
        CopySourceRange=f"bytes=0-{_PART1_SIZE - 1}")
    etag1 = part1["CopyPartResult"]["ETag"]
    assert etag1 == part1_expected, (
        f"UploadPartCopy part 1 ETag {etag1!r}, expected the MD5 of its range {part1_expected!r}"
    )

    part2 = s3.upload_part_copy(
        Bucket=bucket, Key=dest_key, UploadId=upload_id, PartNumber=2,
        CopySource={"Bucket": bucket, "Key": src_key},
        CopySourceRange=f"bytes={_PART1_SIZE}-{_PART1_SIZE + _PART2_SIZE - 1}")
    etag2 = part2["CopyPartResult"]["ETag"]
    assert etag2 == part2_expected, (
        f"UploadPartCopy part 2 ETag {etag2!r}, expected the MD5 of its range {part2_expected!r}"
    )

    expected_final = _composite_etag([etag1, etag2], 2)
    complete = s3.complete_multipart_upload(
        Bucket=bucket, Key=dest_key, UploadId=upload_id,
        MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": etag1},
            {"PartNumber": 2, "ETag": etag2},
        ]})
    final_etag = complete["ETag"]
    assert final_etag == expected_final, (
        f"CompleteMultipartUpload ETag {final_etag!r}, expected {expected_final!r}"
    )
    assert final_etag.endswith('-2"'), f"CompleteMultipartUpload ETag {final_etag!r} does not end '-2'"

    got = s3.get_object(Bucket=bucket, Key=dest_key)["Body"].read()
    assert got == body, f"assembled object is {len(got)} bytes, expected {len(body)} matching the source"

    # === refusal: the same copy with the '+' spelled as a space targets a key that never existed ===
    bad_key = src_key.replace("+", " ")
    assert bad_key != src_key, "the substitution produced the same key, which defeats the probe"

    dest_key2 = "dest/rejected.bin"
    create2 = s3.create_multipart_upload(Bucket=bucket, Key=dest_key2)
    upload_id2 = create2["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, dest_key2, upload_id2))

    code, message = _error(lambda: s3.upload_part_copy(
        Bucket=bucket, Key=dest_key2, UploadId=upload_id2, PartNumber=1,
        CopySource={"Bucket": bucket, "Key": bad_key}))
    assert (code, message) == _NO_SUCH_KEY, (
        f"UploadPartCopy with the plus spelled as a space returned {(code, message)!r}, "
        f"expected {_NO_SUCH_KEY!r}"
    )

    parts = s3.list_parts(Bucket=bucket, Key=dest_key2, UploadId=upload_id2).get("Parts") or []
    assert parts == [], f"a rejected UploadPartCopy recorded a part anyway: {parts!r}"

    # Positive control in the same upload: the correctly spelled key still completes it.
    part_ctrl = s3.upload_part_copy(
        Bucket=bucket, Key=dest_key2, UploadId=upload_id2, PartNumber=1,
        CopySource={"Bucket": bucket, "Key": src_key})
    etag_ctrl = part_ctrl["CopyPartResult"]["ETag"]
    expected_ctrl = _quoted_md5(body)
    assert etag_ctrl == expected_ctrl, (
        f"UploadPartCopy of the correctly spelled key returned {etag_ctrl!r}, expected {expected_ctrl!r}"
    )

    expected_final2 = _composite_etag([etag_ctrl], 1)
    complete2 = s3.complete_multipart_upload(
        Bucket=bucket, Key=dest_key2, UploadId=upload_id2,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag_ctrl}]})
    final_etag2 = complete2["ETag"]
    assert final_etag2 == expected_final2, (
        f"CompleteMultipartUpload ETag {final_etag2!r}, expected {expected_final2!r}"
    )

    got2 = s3.get_object(Bucket=bucket, Key=dest_key2)["Body"].read()
    assert got2 == body, (
        f"the surviving upload assembled {len(got2)} bytes, expected {len(body)} matching the source"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
