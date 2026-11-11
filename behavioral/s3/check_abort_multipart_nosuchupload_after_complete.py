"""abort-multipart-nosuchupload-after-complete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "abort-multipart-nosuchupload-after-complete"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AbortMultipartUpload after CompleteMultipartUpload succeeds as a no-op and leaves the completed
    object intact with its full ContentLength."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "mpu-object.bin"
    body = b"x" * 1024

    create = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = create["UploadId"]

    part = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=body
    )
    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"ETag": part["ETag"], "PartNumber": 1}]},
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # The completed object really exists now.
    s3.head_object(Bucket=bucket, Key=key)

    # Real S3: aborting an upload id that has already been finalized by
    # CompleteMultipartUpload succeeds silently (no NoSuchUpload) rather than
    # erroring -- it is a genuine no-op, not a resurrection of the abort path.
    _expect_success(
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id),
        "AbortMultipartUpload on an already-completed upload id",
    )

    # The already-completed object must be completely unaffected by the abort.
    still_there = s3.head_object(Bucket=bucket, Key=key)
    assert still_there["ContentLength"] == len(body), (
        "abort of an already-completed multipart upload must not disturb the "
        "finalized object"
    )


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_object_versions(Bucket=name)
            for v in resp.get("Versions", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
            for m in resp.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=m["Key"], VersionId=m["VersionId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=name):
                for u in page.get("Uploads", []):
                    s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _expect_success(fn, what):
    """Call fn(); a ClientError raises AssertionError naming its code, since the claim is that
    the call succeeds as a no-op."""
    try:
        return fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            f"expected {what} to succeed as a no-op, got {err.get('Code')!r}: {err.get('Message')!r}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
