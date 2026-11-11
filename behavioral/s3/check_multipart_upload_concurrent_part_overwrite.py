"""multipart-upload-concurrent-part-overwrite."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multipart-upload-concurrent-part-overwrite"
GROUP = "concurrency"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-uploading a PartNumber replaces its stored ETag and size in ListParts; completing with the
    stale ETag fails with InvalidPart and its exact message and creates no object, and completing with
    the latest ETag yields only the latest part's bytes."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mpuoverwrite-")
    _create_bucket(ctx, s3, bucket)

    key = "assembled-object.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    ctx.on_cleanup(lambda: _abort_if_pending(ctx, bucket, key, upload_id))

    part_v1 = b"A" * (64 * 1024)
    part_v2 = b"B" * (128 * 1024)

    etag_v1 = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=part_v1
    )["ETag"]
    etag_v2 = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=part_v2
    )["ETag"]

    assert etag_v1 != etag_v2, "re-uploading the same part number should change its ETag"

    # ListParts reflects only the latest overwrite for that part number, not both
    parts = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)["Parts"]
    assert len(parts) == 1, f"expected exactly one part after overwrite, got {len(parts)}"
    assert parts[0]["PartNumber"] == 1, f"expected PartNumber 1, got {parts[0]['PartNumber']}"
    assert parts[0]["ETag"] == etag_v2, f"expected ListParts ETag to be the latest {etag_v2}, got {parts[0]['ETag']}"
    assert parts[0]["Size"] == len(part_v2), f"expected ListParts Size {len(part_v2)}, got {parts[0]['Size']}"

    # completing against the now-stale first ETag is rejected
    stale_err, stale_message = _error_code(
        lambda: s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"ETag": etag_v1, "PartNumber": 1}]},
        )
    )
    assert stale_err == "InvalidPart", f"expected InvalidPart for stale ETag, got {stale_err}"
    assert stale_message == "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.", stale_message

    # the rejected completion must not have assembled the object -- independent read confirms absence
    absent_err, absent_message = _error_code(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert absent_err == "NoSuchKey", (
        f"object must not exist after the stale-ETag completion was rejected, got {absent_err!r}"
    )
    assert absent_message == "The specified key does not exist.", absent_message

    # completing against the latest ETag succeeds and assembles only the v2 bytes
    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"ETag": etag_v2, "PartNumber": 1}]},
    )
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == part_v2, f"expected assembled object to contain only v2 bytes, got {len(body)} bytes of other content"
    assert len(body) == len(part_v2), f"expected object length {len(part_v2)}, got {len(body)}"


def _error_code(fn) -> tuple:
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _abort_if_pending(ctx, bucket: str, key: str, upload_id: str) -> None:
    s3 = ctx.client("s3")
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
