"""deep-s3-immutability-upload-part-wrong-sha256-rejected-slot-stays-empty."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-upload-part-wrong-sha256-rejected-slot-stays-empty"
GROUP = 'multipart-identity-rejection'
SERVICES = ['s3']

_PART1_LEN = 5 * 1024 * 1024  # the minimum size of a non-final part
_PART2 = b"the-true-second-part-" * 200


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


def _error_code(fn, what):
    """Call fn(); return the S3 (code, message) it raised. A SUCCESS is itself the failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"{what} unexpectedly SUCCEEDED (HTTP "
        f"{resp.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}) where real AWS refuses it"
    )


def _listed_parts(s3, bucket, key, upload_id):
    out = []
    for page in s3.get_paginator("list_parts").paginate(Bucket=bucket, Key=key, UploadId=upload_id):
        out += [(p["PartNumber"], p.get("ChecksumSHA256")) for p in page.get("Parts", [])]
    return out


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An UploadPart whose declared SHA256 does not match its bytes is rejected with BadDigest and
    leaves its slot empty in ListParts; the slot then accepts the true digest, and the completed
    object is built only from the parts that verified."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "verified.bin"
    part1 = bytes((i * 11 + 1) % 241 for i in range(_PART1_LEN))

    up = s3.create_multipart_upload(Bucket=bucket, Key=key, ChecksumAlgorithm="SHA256")
    upload_id = up["UploadId"]
    ctx.on_cleanup(lambda: _abort_quietly(s3, bucket, key, upload_id))

    r1 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part1,
        ChecksumSHA256=_b64sha256(part1),
    )
    assert r1.get("ChecksumSHA256") == _b64sha256(part1), (
        f"part 1 echoed ChecksumSHA256 {r1.get('ChecksumSHA256')!r}, want its true sha256"
    )

    # A valid sha256, but of other bytes.
    wrong = _b64sha256(b"these are not the bytes being sent")
    code, message = _error_code(
        lambda: s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=_PART2,
            ChecksumSHA256=wrong,
        ),
        "an UploadPart whose declared ChecksumSHA256 does not match its bytes",
    )
    assert code == "BadDigest", f"expected BadDigest for a mismatched part sha256, got {code!r}"
    want = "The SHA256 you specified did not match the calculated checksum."
    assert message == want, f"expected {want!r}, got {message!r}"

    # Effect absent: the refused part never occupied slot 2.
    listed = _listed_parts(s3, bucket, key, upload_id)
    assert listed == [(1, _b64sha256(part1))], (
        f"after the rejected part 2, ListParts shows {listed!r}; want only part 1"
    )

    # Positive control: the same slot accepts the true digest.
    r2 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=_PART2,
        ChecksumSHA256=_b64sha256(_PART2),
    )
    listed = _listed_parts(s3, bucket, key, upload_id)
    assert listed == [(1, _b64sha256(part1)), (2, _b64sha256(_PART2))], (
        f"after the corrected part 2, ListParts shows {listed!r}; want parts 1 and 2 with true digests"
    )

    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": r1["ETag"], "ChecksumSHA256": r1["ChecksumSHA256"]},
            {"PartNumber": 2, "ETag": r2["ETag"], "ChecksumSHA256": r2["ChecksumSHA256"]},
        ]},
    )
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == part1 + _PART2, (
        f"the completed object is {len(body)} bytes and differs from part1+part2 "
        f"({len(part1) + len(_PART2)} bytes) — the refused part must contribute nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
