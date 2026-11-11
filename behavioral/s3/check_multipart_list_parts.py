"""multipart-list-parts."""

from __future__ import annotations

import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "multipart-list-parts"
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
    """ListParts returns the uploaded parts with correct ETags and sizes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "multipart/list-parts.bin"
    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = mpu["UploadId"]

    part_body = b"P" * (5 * 1024 * 1024)
    r1 = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=part_body
    )

    expected_etag = f'"{hashlib.md5(part_body).hexdigest()}"'
    assert r1["ETag"] == expected_etag, (
        f"upload_part ETag {r1['ETag']!r} != recomputed MD5 {expected_etag!r}"
    )

    resp = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
    parts = resp.get("Parts", [])
    assert len(parts) == 1, f"expected 1 part, got {len(parts)}"
    assert parts[0]["PartNumber"] == 1, f"expected PartNumber 1, got {parts[0]['PartNumber']}"
    assert parts[0]["ETag"] == expected_etag, (
        f"list_parts ETag {parts[0]['ETag']!r} != recomputed MD5 {expected_etag!r}"
    )
    assert parts[0]["Size"] == len(part_body), (
        f"expected Size {len(part_body)}, got {parts[0]['Size']}"
    )

    # Cleanup
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
