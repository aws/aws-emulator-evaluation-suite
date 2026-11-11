"""multipart-complete-invalid-part-etag-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-complete-invalid-part-etag-rejected"
GROUP = 'multipart'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers), abort dangling multipart
    uploads, then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
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
    """CompleteMultipartUpload with a mismatched part ETag must fail with InvalidPart
    (overly-permissive boundary); the rejected call must not materialise the object, and
    the upload must still be abortable afterward -- and gone-and-unusable once aborted."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "mpu-badpart.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=b"y" * 1024)

    code, message = _error(lambda: s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"00000000000000000000000000000000"'}]},
    ))
    assert code == "InvalidPart", f"expected InvalidPart, got {code!r}"
    assert message == "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.", message

    # the rejected completion must not have materialised the object
    # HeadObject's 404 carries no body, so there is no AWS message to assert.
    head_code, _ = _error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert head_code == "404", f"object must not exist after a rejected completion, got {head_code!r}"

    # upload must still be abortable/cleanup-able after the failed completion
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    # ...and gone-and-unusable once aborted
    gone_code, gone_message = _error(lambda: s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id))
    assert gone_code == "NoSuchUpload", f"expected NoSuchUpload after abort, got {gone_code!r}"
    assert gone_message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", gone_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
