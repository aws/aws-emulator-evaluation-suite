"""lifecycle-abort-incomplete-multipart."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "lifecycle-abort-incomplete-multipart"
GROUP = 'lifecycle_rules'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AbortIncompleteMultipartUpload lifecycle rule is accepted and reflected by GetBucketLifecycleConfiguration.

    A fresh (not-yet-stale) multipart upload matching its prefix is still listed by ListMultipartUploads --
    the actual auto-abort fires only once the real DaysAfterInitiation window (minimum 1 day) elapses.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "sim2real-ttl-abort-mpu-rule",
                    "Filter": {"Prefix": "mpu-ttl-"},
                    "Status": "Enabled",
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                }
            ]
        },
    )

    cfg = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    (rule,) = [r for r in cfg["Rules"] if r["ID"] == "sim2real-ttl-abort-mpu-rule"]
    assert rule["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"] == 1, (
        f"expected DaysAfterInitiation=1 reflected back, got {rule}"
    )

    key = "mpu-ttl-stale-upload.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    try:
        uploads = s3.list_multipart_uploads(Bucket=bucket, Prefix="mpu-ttl-")["Uploads"]
        upload_ids = {u["UploadId"] for u in uploads}
        assert upload_id in upload_ids, (
            "expected the fresh (not yet past its DaysAfterInitiation TTL) upload still listed"
        )
    finally:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    uploads_after_abort = s3.list_multipart_uploads(Bucket=bucket, Prefix="mpu-ttl-").get("Uploads", [])
    assert upload_id not in {u["UploadId"] for u in uploads_after_abort}, (
        f"expected upload_id={upload_id} gone from ListMultipartUploads after AbortMultipartUpload, "
        f"still present: {uploads_after_abort}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
