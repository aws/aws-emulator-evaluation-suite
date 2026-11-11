"""multipart-etag-format."""

from __future__ import annotations

import re

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "multipart-etag-format"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Completed multipart object ETag contains a dash and part count (e.g. '...-2')."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "multipart/etag-format.bin"
    part_body = b"E" * (5 * 1024 * 1024)

    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = mpu["UploadId"]

    r1 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part_body
    )
    r2 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=2, Body=part_body
    )

    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"PartNumber": 1, "ETag": r1["ETag"]},
                {"PartNumber": 2, "ETag": r2["ETag"]},
            ]
        },
    )
    head = s3.head_object(Bucket=bucket, Key=key)
    etag = head["ETag"].strip('"')
    # Multipart ETags have format: <32-hex-digest>-<part_count>. A bare substring test
    # ("-2" in etag) would wrongly accept "-20".."-29", so match the whole thing.
    m = re.fullmatch(r"[0-9a-f]{32}-(\d+)", etag)
    assert m is not None, f"multipart ETag should be '<32-hex-digest>-<part_count>', got: {etag}"
    assert m.group(1) == "2", f"multipart ETag part count should be exactly '2', got: {etag}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
