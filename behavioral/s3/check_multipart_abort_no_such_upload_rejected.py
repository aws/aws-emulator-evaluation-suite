"""multipart-abort-no-such-upload-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-abort-no-such-upload-rejected"
GROUP = 'multipart'
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


def _err_code(fn):
    """Call fn(); return botocore (Code, Message) if a ClientError is raised.
    An unexpected success raises, so an accepted bogus uploadId cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _uploads(s3, bucket):
    return s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])


def _abort_if_present(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AbortMultipartUpload with a never-issued uploadId raises NoSuchUpload and leaves a real
    in-flight upload on the same bucket untouched (per ListMultipartUploads before and after);
    the identical call against the real upload id succeeds."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "real-upload.bin"

    real_upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_if_present(s3, bucket, key, real_upload_id))
    before = _uploads(s3, bucket)
    assert len(before) == 1 and before[0]["UploadId"] == real_upload_id, (
        f"the positive-control upload did not appear in ListMultipartUploads: {before!r}"
    )

    fake_upload_id = "sim2real-behav-fake-upload-id-0000000000"
    code, message = _err_code(
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key="never-uploaded.bin", UploadId=fake_upload_id)
    )
    assert code == "NoSuchUpload", f"expected NoSuchUpload for a fabricated uploadId, got {code}"
    assert message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", message

    after = _uploads(s3, bucket)
    assert len(after) == 1 and after[0]["UploadId"] == real_upload_id, (
        f"the rejected abort on a fabricated uploadId changed the real upload's listing: {after!r}"
    )

    # The identical shape of call succeeds against the real upload id: the rejection above was
    # specific to the fabricated id, not to AbortMultipartUpload itself.
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=real_upload_id)
    gone = _uploads(s3, bucket)
    assert gone == [], f"the real upload was not removed by its own abort: {gone!r}"

    # And the now-aborted real id is itself a dead id: a further operation against it fails
    # with the same specific code.
    code2, message2 = _err_code(lambda: s3.list_parts(Bucket=bucket, Key=key, UploadId=real_upload_id))
    assert code2 == "NoSuchUpload", f"expected NoSuchUpload against the aborted upload id, got {code2}"
    assert message2 == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
