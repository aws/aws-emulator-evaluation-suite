"""deep-s3-immutability-composite-sha256-checksum-reports-parts."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-composite-sha256-checksum-reports-parts"
GROUP = 'multipart-identity'
SERVICES = ['s3']

_PART1_LEN = 5 * 1024 * 1024  # the minimum size of a non-final part
_PART2 = b"sha256-tail-" * 400  # 4800 bytes


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


def _b64sha256(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A SHA256 multipart object stores a COMPOSITE checksum (sha256 of part digests, '-<parts>')
    that GetObjectAttributes reports with each part's checksum; a single PUT stores FULL_OBJECT.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    part1 = bytes((i * 13 + 5) % 253 for i in range(_PART1_LEN))
    whole = part1 + _PART2

    up = s3.create_multipart_upload(Bucket=bucket, Key="multi.bin", ChecksumAlgorithm="SHA256")
    upload_id = up["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, "multi.bin", upload_id))
    assert up.get("ChecksumAlgorithm") == "SHA256" and up.get("ChecksumType") == "COMPOSITE", (
        f"CreateMultipartUpload echoed ChecksumAlgorithm {up.get('ChecksumAlgorithm')!r}, "
        f"ChecksumType {up.get('ChecksumType')!r}; want SHA256 / COMPOSITE (the SHA256 default)"
    )

    parts = []
    for number, data in ((1, part1), (2, _PART2)):
        r = s3.upload_part(
            Bucket=bucket, Key="multi.bin", UploadId=upload_id, PartNumber=number, Body=data,
            ChecksumAlgorithm="SHA256",
        )
        assert r.get("ChecksumSHA256") == _b64sha256(data), (
            f"part {number} ChecksumSHA256 {r.get('ChecksumSHA256')!r} != sha256 of its bytes"
        )
        parts.append({"PartNumber": number, "ETag": r["ETag"], "ChecksumSHA256": r["ChecksumSHA256"]})

    digest = base64.b64encode(
        hashlib.sha256(hashlib.sha256(part1).digest() + hashlib.sha256(_PART2).digest()).digest()
    ).decode()
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key="multi.bin", UploadId=upload_id, MultipartUpload={"Parts": parts}
    )
    assert done.get("ChecksumSHA256") == f"{digest}-2", (
        f"CompleteMultipartUpload ChecksumSHA256 {done.get('ChecksumSHA256')!r}; want "
        f"sha256(sha256(p1)||sha256(p2)) + '-2' = {digest + '-2'!r}"
    )
    assert done.get("ChecksumType") == "COMPOSITE", (
        f"CompleteMultipartUpload ChecksumType {done.get('ChecksumType')!r}, want 'COMPOSITE'"
    )
    assert digest != _b64sha256(whole), "the composite digest collided with the whole-object sha256"

    got = s3.get_object(Bucket=bucket, Key="multi.bin", ChecksumMode="ENABLED")
    body = got["Body"].read()
    assert body == whole, "the multipart object's bytes differ from what was uploaded"
    assert got.get("ChecksumSHA256") == f"{digest}-2" and got.get("ChecksumType") == "COMPOSITE", (
        f"GetObject reported ChecksumSHA256 {got.get('ChecksumSHA256')!r} / ChecksumType "
        f"{got.get('ChecksumType')!r}; want {digest + '-2'!r} / COMPOSITE"
    )

    # GetObjectAttributes returns the composite digest without the '-N' suffix other calls carry.
    attrs = s3.get_object_attributes(
        Bucket=bucket, Key="multi.bin", ObjectAttributes=["Checksum", "ObjectParts", "ObjectSize"]
    )
    assert attrs["Checksum"] == {"ChecksumSHA256": digest, "ChecksumType": "COMPOSITE"}, (
        f"GetObjectAttributes Checksum {attrs.get('Checksum')!r}; want the composite digest "
        f"{digest!r} (no '-N' in this view) with ChecksumType COMPOSITE"
    )
    assert attrs["ObjectSize"] == len(whole), f"ObjectSize {attrs['ObjectSize']!r} != {len(whole)}"
    op = attrs["ObjectParts"]
    assert op["TotalPartsCount"] == 2 and op["IsTruncated"] is False, (
        f"ObjectParts summary {op!r}; want TotalPartsCount 2, not truncated"
    )
    listed = [(p["PartNumber"], p["Size"], p["ChecksumSHA256"]) for p in op["Parts"]]
    assert listed == [(1, len(part1), _b64sha256(part1)), (2, len(_PART2), _b64sha256(_PART2))], (
        f"ObjectParts.Parts {listed!r} do not reproduce the uploaded parts' sizes and sha256s"
    )

    # ObjectParts paginates on PartNumberMarker like ListParts.
    page1 = s3.get_object_attributes(
        Bucket=bucket, Key="multi.bin", ObjectAttributes=["ObjectParts"], MaxParts=1
    )["ObjectParts"]
    assert page1["IsTruncated"] is True and [p["PartNumber"] for p in page1["Parts"]] == [1], (
        f"MaxParts=1 page {page1!r}; want only part 1 and IsTruncated"
    )
    page2 = s3.get_object_attributes(
        Bucket=bucket, Key="multi.bin", ObjectAttributes=["ObjectParts"], MaxParts=1,
        PartNumberMarker=page1["NextPartNumberMarker"],
    )["ObjectParts"]
    assert [p["PartNumber"] for p in page2["Parts"]] == [2] and page2["IsTruncated"] is False, (
        f"the page after marker {page1['NextPartNumberMarker']!r} was {page2!r}; want only part 2"
    )

    # --- Contrast: the identical bytes in ONE PUT store a FULL_OBJECT sha256 of the bytes.
    single = s3.put_object(Bucket=bucket, Key="single.bin", Body=whole, ChecksumAlgorithm="SHA256")
    assert single.get("ChecksumSHA256") == _b64sha256(whole), (
        f"single PUT ChecksumSHA256 {single.get('ChecksumSHA256')!r} != sha256 of the bytes"
    )
    sattrs = s3.get_object_attributes(
        Bucket=bucket, Key="single.bin", ObjectAttributes=["Checksum", "ObjectParts"]
    )
    assert sattrs["Checksum"] == {"ChecksumSHA256": _b64sha256(whole), "ChecksumType": "FULL_OBJECT"}, (
        f"GetObjectAttributes on the single PUT reported {sattrs.get('Checksum')!r}; want the "
        "stored FULL_OBJECT sha256 of the bytes"
    )
    assert "ObjectParts" not in sattrs, (
        f"a single-PUT object reported ObjectParts {sattrs.get('ObjectParts')!r}; it has no parts"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
