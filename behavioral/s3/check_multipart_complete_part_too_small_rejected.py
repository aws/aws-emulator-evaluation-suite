"""multipart-complete-part-too-small-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-complete-part-too-small-rejected"
GROUP = 'multipart'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers + pending multipart uploads) then delete it; best-effort teardown."""
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
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
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


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _abort_if_present(s3, bucket, key, upload_id):
    """Best-effort abort; the upload may already be completed or aborted."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload must reject a non-final part smaller than 5 MiB with EntityTooSmall,
    leaving no object behind -- proven against a positive control showing a correctly-sized
    completion on the same bucket succeeds."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # Positive control: a single-part upload has no non-final part, so the 5 MiB minimum
    # does not apply and completion must succeed. Without this, "rejects a too-small
    # non-final part" would be indistinguishable from "rejects every CompleteMultipartUpload".
    control_key = "mpu-control.bin"
    control_upload_id = s3.create_multipart_upload(Bucket=bucket, Key=control_key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_if_present(s3, bucket, control_key, control_upload_id))
    control_etag = s3.upload_part(
        Bucket=bucket, Key=control_key, PartNumber=1, UploadId=control_upload_id, Body=b"c" * 1024
    )["ETag"]
    s3.complete_multipart_upload(
        Bucket=bucket, Key=control_key, UploadId=control_upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": control_etag}]},
    )
    control_size = s3.head_object(Bucket=bucket, Key=control_key)["ContentLength"]
    assert control_size == 1024, f"positive control: expected a 1024-byte object, got {control_size}"

    # Negative: a non-final part smaller than 5 MiB must be rejected.
    key = "mpu-toosmall.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_if_present(s3, bucket, key, upload_id))
    e1 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=b"a" * 1024)["ETag"]
    e2 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=2, UploadId=upload_id, Body=b"b" * 1024)["ETag"]

    code, message = _error(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]},
    ))
    assert code == "EntityTooSmall", f"expected EntityTooSmall for a 1 KiB non-final part, got {code!r}"
    assert message == "Your proposed upload is smaller than the minimum allowed size", message

    # the object must NOT have been materialised
    # HeadObject's 404 carries no body, so there is no AWS message to assert.
    not_found, _ = _error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert not_found == "404", f"expected the rejected completion to leave no object, got {not_found!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
