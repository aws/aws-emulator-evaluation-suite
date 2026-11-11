"""s3checksum-upload-part-mismatch-rejected-and-the-part-is-absent."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-upload-part-mismatch-rejected-and-the-part-is-absent"
GROUP = 'checksum-rejection'
SERVICES = ['s3']

_PART_SIZE = 5 * 1024 * 1024          # the multipart minimum for every part but the last
_TAIL_SIZE = 2048
_NPARTS = 2


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
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    return name


def _abort_upload(s3, bucket, key, upload_id):
    """Abort a multipart upload; one already completed or aborted counts as done, other errors raise."""
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


def _sha256_b64(data: bytes) -> str:
    """The base64 SHA-256 of ``data``, in the form S3 puts in ChecksumSHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadPart with a well-formed but wrong ChecksumSHA256 is refused with 400 BadDigest and its exact
    message and the part is not listed; completion without it fails with InvalidPart, and re-uploading
    it with the true digest completes the object byte for byte."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "part-verified.bin"

    parts = [b"A" * _PART_SIZE, b"B" * _TAIL_SIZE]
    whole = b"".join(parts)
    assert len(parts) == _NPARTS, f"expected {_NPARTS} parts, built {len(parts)}"

    created = s3.create_multipart_upload(Bucket=bucket, Key=key, ChecksumAlgorithm="SHA256")
    upload_id = created["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))

    # --- Part 1 goes up correctly, so the upload has real state to preserve.
    want_p1 = _sha256_b64(parts[0])
    p1 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=parts[0],
        ChecksumAlgorithm="SHA256", ChecksumSHA256=want_p1,
    )
    assert p1["ChecksumSHA256"] == want_p1, (
        f"UploadPart 1 reported {p1['ChecksumSHA256']!r}, the client computed {want_p1!r}"
    )

    # --- Break exactly one thing: part 2's checksum.
    want_p2 = _sha256_b64(parts[1])
    wrong_p2 = _sha256_b64(parts[1] + b"x")
    assert wrong_p2 != want_p2, "the wrong part digest collided with the correct one"
    assert len(base64.b64decode(wrong_p2)) == 32, (
        f"the wrong part digest must be a well-formed 32-byte SHA-256, got "
        f"{len(base64.b64decode(wrong_p2))} bytes"
    )
    exc = _client_error(
        lambda: s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=parts[1],
            ChecksumAlgorithm="SHA256", ChecksumSHA256=wrong_p2,
        )
    )
    assert exc is not None, (
        f"UploadPart accepted ChecksumSHA256={wrong_p2!r} for a part whose true digest is "
        f"{want_p2!r} — part checksums are being stored rather than verified"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "BadDigest", f"expected BadDigest for a mismatched part checksum, got {code!r}"
    assert status == 400, f"expected HTTP 400 for BadDigest, got {status!r}"
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The SHA256 you specified did not match the calculated checksum.", (
        f"the mismatched part checksum's refusal message is {message!r}"
    )

    # --- Effect absent: the refused part was never registered against the upload.
    registered = []
    for page in s3.get_paginator("list_parts").paginate(
            Bucket=bucket, Key=key, UploadId=upload_id):
        registered += [(p["PartNumber"], p.get("ChecksumSHA256")) for p in page.get("Parts", [])]
    assert registered == [(1, want_p1)], (
        f"ListParts reports {registered!r}; after the refusal only part 1 may be registered, so "
        f"the expected list is {[(1, want_p1)]!r}"
    )

    # --- Effect absent, second reading: the object cannot be completed without part 2.
    incomplete = _client_error(
        lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={"Parts": [
                {"PartNumber": 1, "ETag": p1["ETag"], "ChecksumSHA256": want_p1},
                {"PartNumber": 2, "ETag": p1["ETag"], "ChecksumSHA256": want_p2},
            ]},
        )
    )
    assert incomplete is not None, (
        "CompleteMultipartUpload assembled an object from a part that was never uploaded"
    )
    incomplete_code = incomplete.response.get("Error", {}).get("Code")
    assert incomplete_code == "InvalidPart", (
        f"expected InvalidPart when completing with a part that was refused at upload, got "
        f"{incomplete_code!r}"
    )
    incomplete_message = incomplete.response.get("Error", {}).get("Message")
    assert incomplete_message == (
        "One or more of the specified parts could not be found.  The part may not have been "
        "uploaded, or the specified entity tag may not match the part's entity tag."
    ), f"the incomplete-upload refusal's message is {incomplete_message!r}"
    absent = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert absent is not None, "the failed completion created the object anyway"
    assert absent.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"HeadObject returned {absent.response['ResponseMetadata']['HTTPStatusCode']!r}, "
        "expected 404"
    )

    # --- POSITIVE CONTROL: the identical chunk with its true digest completes the upload.
    p2 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=parts[1],
        ChecksumAlgorithm="SHA256", ChecksumSHA256=want_p2,
    )
    assert p2["ChecksumSHA256"] == want_p2, (
        f"UploadPart 2 reported {p2['ChecksumSHA256']!r}, the client computed {want_p2!r}"
    )
    after = []
    for page in s3.get_paginator("list_parts").paginate(
            Bucket=bucket, Key=key, UploadId=upload_id):
        after += [(p["PartNumber"], p.get("ChecksumSHA256")) for p in page.get("Parts", [])]
    assert after == [(1, want_p1), (2, want_p2)], (
        f"ListParts reports {after!r} after the corrected upload, want "
        f"{[(1, want_p1), (2, want_p2)]!r}"
    )

    want_composite = _sha256_b64(
        b"".join(hashlib.sha256(chunk).digest() for chunk in parts)
    ) + f"-{_NPARTS}"
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": p1["ETag"], "ChecksumSHA256": want_p1},
            {"PartNumber": 2, "ETag": p2["ETag"], "ChecksumSHA256": want_p2},
        ]},
    )
    assert done["ChecksumSHA256"] == want_composite, (
        f"the completion reported {done['ChecksumSHA256']!r}; the composite of these two part "
        f"digests is {want_composite!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    body = got["Body"].read()
    assert body == whole, (
        f"the assembled object is {len(body)} bytes, want {len(whole)}; the part that was refused "
        "and re-uploaded must appear exactly once, in order"
    )
    assert got["ChecksumSHA256"] == want_composite, (
        f"GetObject reported {got['ChecksumSHA256']!r}, want {want_composite!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
