"""conc-s3-conditional-writes-complete-multipart-stale-if-match-rejected."""

from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-complete-multipart-stale-if-match-rejected"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_MIB = 1024 * 1024
_PRECONDITION_MSG = 'At least one of the pre-conditions you specified did not hold'


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort_upload(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchUpload":
            raise


def _start_upload(ctx, s3, bucket, key):
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_upload(s3, bucket, key, upload_id))
    return upload_id


def _upload_parts(s3, bucket, key, upload_id, parts):
    out = []
    for n, body in enumerate(parts, start=1):
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=n,
                              Body=body)["ETag"]
        out.append({"PartNumber": n, "ETag": etag})
    return out


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


def _message(exc):
    return exc.response.get("Error", {}).get("Message")


def _pattern(tag, size):
    unit = hashlib.sha256(tag.encode()).digest()
    return (unit * (size // len(unit) + 1))[:size]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload with an If-Match ETag made stale by a concurrent overwrite is refused with
    412 PreconditionFailed and its exact message and keeps the overwriter's bytes; the same completion
    naming the current ETag replaces the object with exactly part1 + part2."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "optimistic/document.bin"
    part1 = _pattern("mpu-part-one", 5 * _MIB)
    part2 = _pattern("mpu-part-two", 77_777)

    original = b"version-read-by-the-uploader-before-it-started"
    stale_etag = s3.put_object(Bucket=bucket, Key=key, Body=original)["ETag"]

    upload = _start_upload(ctx, s3, bucket, key)
    parts = _upload_parts(s3, bucket, key, upload, [part1, part2])

    # A concurrent writer overwrites the key while the upload is still open.
    overwrite = b"concurrent-writer-replaced-the-object-mid-upload"
    current_etag = s3.put_object(Bucket=bucket, Key=key, Body=overwrite)["ETag"]
    assert current_etag != stale_etag, (
        f"the overwrite kept ETag {current_etag!r}; the check cannot tell stale from current"
    )

    # --- Break exactly one thing: complete conditioned on the ETag that is no longer current.
    exc = _client_error(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload,
        MultipartUpload={"Parts": parts}, IfMatch=stale_etag,
    ), f"CompleteMultipartUpload If-Match {stale_etag!r} succeeded although the current ETag is "
       f"{current_etag!r}; the concurrent writer's data was silently discarded")
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code!r}"
    assert _message(exc) == _PRECONDITION_MSG, (
        f"expected message {_PRECONDITION_MSG!r}, got {_message(exc)!r}"
    )
    assert status == 412, f"expected HTTP 412, got {status!r}"

    # --- Effect absent: the concurrent writer's object survives exactly.
    got = s3.get_object(Bucket=bucket, Key=key)
    now = got["Body"].read()
    assert now == overwrite, (
        f"the refused completion changed the object to {len(now)} bytes; want the "
        f"{len(overwrite)}-byte concurrent overwrite"
    )
    assert got["ETag"] == current_etag, (
        f"object ETag is {got['ETag']!r}, want the untouched {current_etag!r}"
    )

    # --- POSITIVE CONTROL: a fresh upload conditioned on the CURRENT ETag replaces the object.
    retry_upload = _start_upload(ctx, s3, bucket, key)
    retry_parts = _upload_parts(s3, bucket, key, retry_upload, [part1, part2])
    done = s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=retry_upload,
        MultipartUpload={"Parts": retry_parts}, IfMatch=current_etag,
    )
    assert done["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"If-Match with the current ETag returned {done['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    after = s3.get_object(Bucket=bucket, Key=key)
    body = after["Body"].read()
    assert body == part1 + part2, (
        f"after the conditional completion the object is {len(body)} bytes (sha256 "
        f"{hashlib.sha256(body).hexdigest()}), want exactly part1+part2"
    )
    assert after["ETag"] == done["ETag"] != current_etag, (
        f"GET ETag {after['ETag']!r}, completion ETag {done['ETag']!r}, previous "
        f"{current_etag!r}: want GET == completion and both new"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
