"""multipart-list-parts-after-abort-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-list-parts-after-abort-rejected"
GROUP = 'multipart'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListParts on an aborted UploadId fails with NoSuchUpload and its exact message, and so does
    UploadPart on it, while the same ListParts on the live upload returned the uploaded part's ETag."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "parts-aborted-obj"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]

    part_body = b"P" * 1024
    part = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part_body)

    live = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
    live_parts = live["Parts"]
    assert len(live_parts) == 1, f"expected 1 live part before abort, got {len(live_parts)}"
    assert live_parts[0]["ETag"] == part["ETag"], (
        f"live ListParts ETag {live_parts[0]['ETag']!r} must match UploadPart's {part['ETag']!r}"
    )

    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    code, message = _error(lambda: s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id))
    assert code == "NoSuchUpload", f"expected NoSuchUpload, got {code!r}"
    assert message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", message

    mutate_code, mutate_message = _error(
        lambda: s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=b"x")
    )
    assert mutate_code == "NoSuchUpload", (
        f"expected NoSuchUpload for UploadPart against an aborted upload, got {mutate_code!r}"
    )
    assert mutate_message == "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.", mutate_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
