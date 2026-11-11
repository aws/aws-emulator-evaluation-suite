"""multipart-abort."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-abort"
GROUP = 'multipart'
SERVICES = ['s3']

ERR_NO_SUCH_UPLOAD = "NoSuchUpload"

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
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AbortMultipartUpload prevents completion and cleans up."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "multipart/aborted.bin"
    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = mpu["UploadId"]

    s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=b"X" * (5 * 1024 * 1024)
    )
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    # ListParts after abort should fail with NoSuchUpload: the upload id is gone, not just idle.
    code, message = _error(lambda: s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id))
    assert code == ERR_NO_SUCH_UPLOAD, f"expected {ERR_NO_SUCH_UPLOAD}, got {code!r}"
    assert message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", message

    # A mutation on the same dead upload id must also fail, not just a read: the id is unusable,
    # not merely unlisted.
    code, message = _error(
        lambda: s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=b"Y" * (5 * 1024 * 1024)
        )
    )
    assert code == ERR_NO_SUCH_UPLOAD, f"expected {ERR_NO_SUCH_UPLOAD} on UploadPart, got {code!r}"
    assert message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
