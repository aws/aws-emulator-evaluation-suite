"""multipart-upload-complete-wrong-part-order-rejected."""
from __future__ import annotations

import os

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multipart-upload-complete-wrong-part-order-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload with a non-ascending Parts list is rejected with InvalidPartOrder and its
    exact message and leaves the upload in progress; the same parts in ascending order complete it with
    the full size and ListMultipartUploads omits the upload."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mpuneg-")
    _create_bucket(ctx, bucket)

    key = "bad-order-object.bin"
    created = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = created["UploadId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        )
    )

    part1_size = 5 * 1024 * 1024
    part2_size = 1 * 1024 * 1024
    part1 = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=os.urandom(part1_size)
    )
    part2 = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=2, UploadId=upload_id, Body=os.urandom(part2_size)
    )

    code, message = _error_code(
        lambda: s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"ETag": part2["ETag"], "PartNumber": 2},
                    {"ETag": part1["ETag"], "PartNumber": 1},
                ]
            },
        )
    )
    assert code == "InvalidPartOrder", f"expected InvalidPartOrder, got {code}"
    assert message == "The list of parts was not in ascending order. Parts must be ordered by part number.", message

    # the upload must still be open (rejected completion did not finalize it)
    listed = s3.list_multipart_uploads(Bucket=bucket)
    upload_ids = [u["UploadId"] for u in listed.get("Uploads", [])]
    assert upload_id in upload_ids, "rejected completion should leave the upload in progress"

    # positive control: the same parts, resubmitted in ascending order, must complete —
    # otherwise a target that rejects every CompleteMultipartUpload call would pass above
    completed = s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"ETag": part1["ETag"], "PartNumber": 1},
                {"ETag": part2["ETag"], "PartNumber": 2},
            ]
        },
    )
    assert completed.get("Key") == key, f"expected completed key {key!r}, got {completed.get('Key')!r}"

    # terminal assertions are independent reads at the destination, not the mutating call's own
    # response
    head = s3.head_object(Bucket=bucket, Key=key)
    expected_size = part1_size + part2_size
    assert head["ContentLength"] == expected_size, (
        f"expected assembled object size {expected_size}, got {head['ContentLength']}"
    )

    listed_after = s3.list_multipart_uploads(Bucket=bucket)
    upload_ids_after = [u["UploadId"] for u in listed_after.get("Uploads", [])]
    assert upload_id not in upload_ids_after, "completed upload should no longer be in progress"


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _cleanup_bucket(ctx, bucket))


def _cleanup_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _error_code(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
