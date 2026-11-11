"""head-object-metadata."""

from __future__ import annotations

import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "head-object-metadata"
GROUP = 'lifecycle'
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """HeadObject returns ContentLength, ContentType, and custom metadata."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"x" * 42
    s3.put_object(
        Bucket=bucket,
        Key="meta.bin",
        Body=body,
        ContentType="application/octet-stream",
        Metadata={"sim2real-key": "sim2real-value"},
    )
    resp = s3.head_object(Bucket=bucket, Key="meta.bin")
    assert resp["ContentLength"] == 42, f"expected ContentLength=42, got {resp.get('ContentLength')}"
    assert resp["ContentType"] == "application/octet-stream", (
        f"expected ContentType=application/octet-stream, got {resp.get('ContentType')}"
    )
    assert resp["Metadata"].get("sim2real-key") == "sim2real-value", (
        f"expected user metadata sim2real-key=sim2real-value, got {resp.get('Metadata')}"
    )
    expected_etag = f'"{hashlib.md5(body).hexdigest()}"'
    assert resp["ETag"] == expected_etag, (
        f"expected ETag {expected_etag} (MD5 of the unencrypted single-part body), got {resp.get('ETag')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
