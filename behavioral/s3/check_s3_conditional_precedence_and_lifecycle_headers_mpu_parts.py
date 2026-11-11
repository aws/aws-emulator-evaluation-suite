"""s3-conditional-precedence-and-lifecycle-headers-mpu-parts."""

from __future__ import annotations

import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-conditional-precedence-and-lifecycle-headers-mpu-parts"
GROUP = 'multipart'
SERVICES = ['s3']

_MIB = 1024 * 1024
# Unequal sizes on purpose: with equal parts a target could derive every Content-Range from
# part_number * part_size and still pass. Parts 1 and 2 are above the 5 MiB minimum for a
# non-final part; part 3 is the small final part.
_SIZES = (5 * _MIB + 123, 6 * _MIB + 7, 777_001)


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
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


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket, register abort+empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-s3cond-parts-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort(s3, bucket, key, upload_id):
    """Abort a multipart upload; one already completed or aborted counts as done, other errors raise."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _headers(resp):
    return {k.lower(): v for k, v in resp["ResponseMetadata"]["HTTPHeaders"].items()}


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetObject with partNumber on a three-part object of unequal parts answers 206 for each part with
    x-amz-mp-parts-count 3, the exact Content-Range and Content-Length of that part, and its uploaded
    bytes, matching a Range GET over the same span."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "parts/three-part.bin"
    chunks = [bytes([0x41 + i]) * size for i, size in enumerate(_SIZES)]
    total = sum(_SIZES)

    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload_id))
    parts = []
    for number, chunk in enumerate(chunks, start=1):
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number,
                              Body=chunk)["ETag"]
        parts.append({"ETag": etag, "PartNumber": number})
    done = s3.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id,
                                        MultipartUpload={"Parts": parts})
    object_etag = done["ETag"]
    assert object_etag.strip('"').endswith("-3"), (
        f"a 3-part object's ETag must end in '-3', got {object_etag!r}"
    )

    # --- Control: a whole-object GET carries no part framing.
    whole = s3.get_object(Bucket=bucket, Key=key)
    whdrs = _headers(whole)
    assert whole["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"a whole-object GET must be 200, got {whole['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert "x-amz-mp-parts-count" not in whdrs and "content-range" not in whdrs, (
        f"a whole-object GET must carry neither x-amz-mp-parts-count nor Content-Range, got "
        f"{ {h: whdrs[h] for h in ('x-amz-mp-parts-count', 'content-range') if h in whdrs}!r}"
    )
    whole_body = whole["Body"].read()
    assert hashlib.sha256(whole_body).digest() == hashlib.sha256(b"".join(chunks)).digest(), (
        f"the reassembled object ({len(whole_body)} bytes) is not the three parts in order"
    )

    offset = 0
    for number, chunk in enumerate(chunks, start=1):
        start, end = offset, offset + len(chunk) - 1
        offset += len(chunk)
        got = s3.get_object(Bucket=bucket, Key=key, PartNumber=number)
        hdrs = _headers(got)
        status = got["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 206, f"part {number}: a part-scoped GET must be 206, got {status}"
        assert hdrs.get("x-amz-mp-parts-count") == "3", (
            f"part {number}: x-amz-mp-parts-count must be '3', got {hdrs.get('x-amz-mp-parts-count')!r}"
        )
        want_range = f"bytes {start}-{end}/{total}"
        assert hdrs.get("content-range") == want_range, (
            f"part {number}: Content-Range must be {want_range!r} (the uploaded byte span), "
            f"got {hdrs.get('content-range')!r}"
        )
        assert int(hdrs.get("content-length", -1)) == len(chunk), (
            f"part {number}: Content-Length must be {len(chunk)}, got {hdrs.get('content-length')!r}"
        )
        assert got["ETag"] == object_etag, (
            f"part {number}: a part-scoped GET reports the OBJECT's ETag {object_etag!r}, got "
            f"{got['ETag']!r}"
        )
        body = got["Body"].read()
        assert hashlib.md5(body).digest() == hashlib.md5(chunk).digest(), (
            f"part {number}: body ({len(body)} bytes, first {body[:4]!r}) is not the uploaded part "
            f"({len(chunk)} bytes of {chunk[:1]!r})"
        )
        ranged = s3.get_object(Bucket=bucket, Key=key, Range=f"bytes={start}-{end}")
        assert ranged["Body"].read() == body, (
            f"part {number}: the bytes at Range {start}-{end} differ from the partNumber read"
        )
    assert offset == total, f"part offsets summed to {offset}, object is {total} bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
