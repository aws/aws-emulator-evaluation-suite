"""multipart-part-number-ordering."""

from __future__ import annotations

import os

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "multipart-part-number-ordering"
GROUP = 'multipart'
SERVICES = ['s3']

MIN_PART_SIZE = 5 * 1024 * 1024  # S3 multipart minimum part size (except last part)

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Parts uploaded out of numeric order are assembled by ascending PartNumber.

    On CompleteMultipartUpload the assembled body must equal part1+part2 (numeric order)
    even though part2 was physically uploaded to S3 first.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "mp-partorder-obj"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]

    part1_data = os.urandom(MIN_PART_SIZE)
    part2_data = os.urandom(1024)

    # Upload part 2 first, then part 1 -- deliberately out of numeric order.
    p2 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=2, UploadId=upload_id, Body=part2_data)
    p1 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=part1_data)

    s3.complete_multipart_upload(
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

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == part1_data + part2_data, (
        "assembled object must be ordered by ascending PartNumber, not by upload arrival order"
    )
    assert len(body) == MIN_PART_SIZE + 1024, (
        f"expected assembled size {MIN_PART_SIZE + 1024}, got {len(body)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
