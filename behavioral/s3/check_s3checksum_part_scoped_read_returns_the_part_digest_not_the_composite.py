"""s3checksum-part-scoped-read-returns-the-part-digest-not-the-composite."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-part-scoped-read-returns-the-part-digest-not-the-composite"
GROUP = 'checksum-semantics'
SERVICES = ['s3']

_PART_SIZE = 5 * 1024 * 1024          # the multipart minimum for every part but the last
_TAIL_SIZE = 4096
_NPARTS = 3


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
    """Best-effort abort of a possibly-already-completed multipart upload (teardown only)."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _sha256_b64(data: bytes) -> str:
    """The base64 SHA-256 of ``data``, in the form S3 puts in ChecksumSHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A part-scoped GET/HEAD returns that part's own SHA256; a whole-object read, the composite.

    Parallel downloaders verify each fetched part against its own digest, so S3 must keep per-part
    digests; every expected value is computed locally with hashlib.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "part-digests.bin"

    parts = [bytes([80 + i]) * _PART_SIZE for i in range(_NPARTS - 1)] + [b"t" * _TAIL_SIZE]
    whole = b"".join(parts)
    part_digests = [_sha256_b64(chunk) for chunk in parts]
    assert len(set(part_digests)) == _NPARTS, (
        f"the {_NPARTS} parts must have distinct digests for a per-part read to be meaningful; "
        f"got {part_digests!r}"
    )
    want_composite = _sha256_b64(
        b"".join(hashlib.sha256(chunk).digest() for chunk in parts)
    ) + f"-{_NPARTS}"

    created = s3.create_multipart_upload(Bucket=bucket, Key=key, ChecksumAlgorithm="SHA256")
    upload_id = created["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))

    completed = []
    for number, chunk in enumerate(parts, start=1):
        uploaded = s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number, Body=chunk,
            ChecksumAlgorithm="SHA256", ChecksumSHA256=part_digests[number - 1],
        )
        assert uploaded["ChecksumSHA256"] == part_digests[number - 1], (
            f"UploadPart {number} reported {uploaded['ChecksumSHA256']!r}, the client computed "
            f"{part_digests[number - 1]!r}"
        )
        completed.append({
            "PartNumber": number,
            "ETag": uploaded["ETag"],
            "ChecksumSHA256": uploaded["ChecksumSHA256"],
        })
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": completed},
    )
    assert done["ChecksumSHA256"] == want_composite, (
        f"the completion reported {done['ChecksumSHA256']!r}, the client computed the composite "
        f"{want_composite!r}"
    )

    # --- The whole-object read returns the composite, for both GET and HEAD.
    whole_get = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert whole_get["ChecksumSHA256"] == want_composite, (
        f"a whole-object GET reported {whole_get['ChecksumSHA256']!r}, want {want_composite!r}"
    )
    assert whole_get["Body"].read() == whole, (
        f"the whole-object GET did not return the {len(whole)} bytes that were uploaded"
    )
    whole_head = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert whole_head["ChecksumSHA256"] == want_composite, (
        f"a whole-object HEAD reported {whole_head['ChecksumSHA256']!r}, want {want_composite!r}"
    )

    # --- Each part-scoped read returns THAT part's digest and THAT part's bytes.
    for number, chunk in enumerate(parts, start=1):
        want = part_digests[number - 1]
        part_get = s3.get_object(
            Bucket=bucket, Key=key, PartNumber=number, ChecksumMode="ENABLED"
        )
        assert part_get["ResponseMetadata"]["HTTPStatusCode"] == 206, (
            f"a part-scoped GET is a partial response; part {number} returned "
            f"{part_get['ResponseMetadata']['HTTPStatusCode']}"
        )
        assert part_get.get("PartsCount") == _NPARTS, (
            f"GET PartNumber={number} reported PartsCount {part_get.get('PartsCount')!r}, want "
            f"{_NPARTS} — the part boundaries were not retained through completion"
        )
        assert part_get["ChecksumSHA256"] == want, (
            f"GET PartNumber={number} reported ChecksumSHA256={part_get['ChecksumSHA256']!r}; the "
            f"client computed {want!r} over that part's {len(chunk)} bytes. Returning the "
            f"composite {want_composite!r} here leaves a verifying downloader unable to check "
            "anything it actually received"
        )
        assert part_get["ChecksumSHA256"] != want_composite, (
            f"GET PartNumber={number} returned the whole object's composite value"
        )
        part_body = part_get["Body"].read()
        assert part_body == chunk, (
            f"GET PartNumber={number} returned {len(part_body)} bytes, want {len(chunk)}"
        )
        assert _sha256_b64(part_body) == part_get["ChecksumSHA256"], (
            f"part {number}: the bytes S3 returned hash to {_sha256_b64(part_body)!r} but S3 "
            f"reported {part_get['ChecksumSHA256']!r} for them"
        )
        part_head = s3.head_object(
            Bucket=bucket, Key=key, PartNumber=number, ChecksumMode="ENABLED"
        )
        assert part_head["ChecksumSHA256"] == want, (
            f"HEAD PartNumber={number} reported {part_head.get('ChecksumSHA256')!r}, want {want!r}"
        )
        assert part_head["ContentLength"] == len(chunk), (
            f"HEAD PartNumber={number} reported ContentLength {part_head['ContentLength']}, want "
            f"{len(chunk)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
