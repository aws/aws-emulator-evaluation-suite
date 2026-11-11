"""multipart-list-uploads-then-abort-nonexistent."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "multipart-list-uploads-then-abort-nonexistent"
GROUP = "state-machine"
SERVICES = ["s3"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMultipartUploads reflects an in-flight upload by key and UploadId; aborting a
    non-existent UploadId returns NoSuchUpload, while aborting the real one succeeds and
    removes it from the listing."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mpu-")
    _create_bucket(ctx, s3, bucket)

    key = "big.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]

    listed = s3.list_multipart_uploads(Bucket=bucket)["Uploads"]
    assert len(listed) == 1, f"expected exactly 1 in-flight upload, got {listed}"
    assert listed[0]["Key"] == key, f"expected key {key!r}, got {listed[0]['Key']!r}"
    assert listed[0]["UploadId"] == upload_id, (
        f"expected UploadId {upload_id!r}, got {listed[0]['UploadId']!r}"
    )

    # Negative: aborting a bogus UploadId for the same key fails specifically.
    code, message = _error(
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId="nonexistent-upload-id-0000")
    )
    assert code == "NoSuchUpload", code
    assert message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", message
    # The real upload is untouched by the failed abort.
    still_listed = s3.list_multipart_uploads(Bucket=bucket)["Uploads"]
    assert len(still_listed) == 1 and still_listed[0]["UploadId"] == upload_id, (
        f"a failed abort must not disturb the real upload, got {still_listed}"
    )

    # Positive control: aborting the real upload id succeeds and removes it from the listing.
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    after = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert after == [], after

    # Aborting the same (already-aborted) upload id again is documented S3 behavior as
    # idempotent: AbortMultipartUpload does not raise NoSuchUpload for an UploadId that
    # this same account already successfully aborted -- it just returns success again.
    # (Only a genuinely bogus/never-issued UploadId, as asserted above, yields
    # NoSuchUpload.) Confirm the repeat abort raises no error and the upload stays gone.
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    after2 = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert after2 == [], after2


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))


def _empty_and_delete_bucket(ctx, s3, name):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
