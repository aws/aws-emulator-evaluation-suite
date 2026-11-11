"""deep-s3-immutability-multipart-etag-is-md5-of-part-md5s."""

from __future__ import annotations

import hashlib
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-multipart-etag-is-md5-of-part-md5s"
GROUP = 'multipart-identity'
SERVICES = ['s3']

_PART1_LEN = 5 * 1024 * 1024  # the minimum size of a non-final part
_PART2 = b"final-part-" * 500  # 5500 bytes; the last part may be any size


def _delete_bucket(client, bucket):
    """Abort open uploads, delete every version and marker, then the bucket."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-imm-")
    params = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort_quietly(s3, bucket, key, upload_id):
    """Abort the upload if it never completed; a completed upload has nothing to abort."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A multipart ETag is exactly md5(concat(part MD5s)) + '-2' while a single PUT of the same bytes
    has ETag md5(bytes); a ranged GET across the part boundary returns the identical slice (206, exact
    Content-Range) from both objects."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    part1 = bytes((i * 7 + 3) % 251 for i in range(_PART1_LEN))
    whole = part1 + _PART2

    up = s3.create_multipart_upload(Bucket=bucket, Key="multi.bin")
    upload_id = up["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, "multi.bin", upload_id))

    parts = []
    for number, data in ((1, part1), (2, _PART2)):
        r = s3.upload_part(
            Bucket=bucket, Key="multi.bin", UploadId=upload_id, PartNumber=number, Body=data
        )
        want = '"' + hashlib.md5(data).hexdigest() + '"'
        assert r["ETag"] == want, f"part {number} ETag {r['ETag']!r} != md5 of its bytes {want!r}"
        parts.append({"PartNumber": number, "ETag": r["ETag"]})

    done = s3.complete_multipart_upload(
        Bucket=bucket, Key="multi.bin", UploadId=upload_id, MultipartUpload={"Parts": parts}
    )
    composite = (
        hashlib.md5(hashlib.md5(part1).digest() + hashlib.md5(_PART2).digest()).hexdigest() + "-2"
    )
    assert done["ETag"] == f'"{composite}"', (
        f"CompleteMultipartUpload ETag {done['ETag']!r}; want md5(md5(p1)||md5(p2))-2 = "
        f"{composite!r}"
    )
    plain = hashlib.md5(whole).hexdigest()
    assert composite.split("-")[0] != plain, "the composite digest collided with the plain MD5"

    head = s3.head_object(Bucket=bucket, Key="multi.bin")
    assert head["ETag"] == f'"{composite}"', f"HeadObject ETag {head['ETag']!r} != {composite!r}"
    assert head["ContentLength"] == len(whole), (
        f"multipart object is {head['ContentLength']!r} bytes, want {len(whole)}"
    )
    part_head = s3.head_object(Bucket=bucket, Key="multi.bin", PartNumber=2)
    assert part_head["ContentLength"] == len(_PART2) and part_head.get("PartsCount") == 2, (
        f"HeadObject PartNumber=2 reported ContentLength {part_head['ContentLength']!r}, "
        f"PartsCount {part_head.get('PartsCount')!r}; want {len(_PART2)} and 2"
    )

    # --- The identical bytes in ONE PUT: the ETag is the plain MD5, and differs from the above.
    single = s3.put_object(Bucket=bucket, Key="single.bin", Body=whole)
    assert single["ETag"] == f'"{plain}"', (
        f"single-PUT ETag {single['ETag']!r}; want the plain MD5 {plain!r}"
    )
    assert re.fullmatch(r'"[0-9a-f]{32}"', single["ETag"]), (
        f"single-PUT ETag {single['ETag']!r} is not a bare 32-hex MD5"
    )
    assert single["ETag"] != done["ETag"], (
        "the single-PUT and multipart ETags are equal; S3 ETags depend on how an object was "
        f"uploaded, not only on its bytes (both {single['ETag']!r})"
    )

    # --- Storage identity regardless of ETag: a Range across the part boundary is byte-exact.
    lo, hi = _PART1_LEN - 10, _PART1_LEN + 9
    want_slice = whole[lo:hi + 1]
    for key, etag in (("multi.bin", done["ETag"]), ("single.bin", single["ETag"])):
        r = s3.get_object(Bucket=bucket, Key=key, Range=f"bytes={lo}-{hi}")
        got = r["Body"].read()
        assert r["ResponseMetadata"]["HTTPStatusCode"] == 206, (
            f"{key}: ranged GET returned HTTP {r['ResponseMetadata']['HTTPStatusCode']!r}, want 206"
        )
        assert r["ContentRange"] == f"bytes {lo}-{hi}/{len(whole)}", (
            f"{key}: Content-Range {r['ContentRange']!r}"
        )
        assert got == want_slice, (
            f"{key}: the range across the part boundary returned {got!r}, want {want_slice!r}"
        )
        assert r["ETag"] == etag, f"{key}: ranged GET ETag {r['ETag']!r} != the object's {etag!r}"

    full = s3.get_object(Bucket=bucket, Key="multi.bin")["Body"].read()
    assert hashlib.md5(full).hexdigest() == plain, (
        "the multipart object's full bytes do not hash to the single-PUT MD5 — the content differs"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
