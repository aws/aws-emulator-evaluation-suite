"""multipart-complete-out-of-order-rejected."""

from __future__ import annotations
import os
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-complete-out-of-order-rejected"
GROUP = 'multipart'
SERVICES = ['s3']

MIN_PART_SIZE = 5 * 1024 * 1024  # S3 multipart minimum part size (except last part)


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteMultipartUpload with parts in descending PartNumber order is rejected with
    InvalidPartOrder and its exact message, the uploaded parts stay listed, and the same upload completes
    as part1 + part2 once the list is ascending."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "mp-badorder-obj"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    part1_body = os.urandom(MIN_PART_SIZE)
    part2_body = b"y" * 1024
    completed = False
    try:
        p1 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=part1_body)
        p2 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=2, UploadId=upload_id, Body=part2_body)

        code, message = _error(
            lambda: s3.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={
                    "Parts": [
                        {"ETag": p2["ETag"], "PartNumber": 2},
                        {"ETag": p1["ETag"], "PartNumber": 1},
                    ]
                },
            )
        )
        assert code == "InvalidPartOrder", f"expected InvalidPartOrder, got {code!r}"
        assert message == "The list of parts was not in ascending order. Parts must be ordered by part number.", message

        # Effect-absent, via an independent read: the rejected attempt must not have consumed
        # or dropped the uploaded parts.
        still = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)["Parts"]
        still_by_number = {p["PartNumber"]: p["ETag"] for p in still}
        assert still_by_number == {1: p1["ETag"], 2: p2["ETag"]}, (
            f"rejected out-of-order completion must not alter the uploaded parts, got {still_by_number}"
        )

        # Restore: the identical upload, with the Parts list corrected to ascending order,
        # must now succeed -- proving the rejection was about order, not a blanket refusal.
        result = s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"ETag": p1["ETag"], "PartNumber": 1},
                    {"ETag": p2["ETag"], "PartNumber": 2},
                ]
            },
        )
        completed = True
        assert result.get("Key") == key, f"unexpected CompleteMultipartUpload response: {result}"

        # Terminal assertion: an independent read at the destination, through a different
        # operation than the one that mutated.
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert body == part1_body + part2_body, "assembled object must equal part1+part2 in order"
    finally:
        if not completed:
            s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
