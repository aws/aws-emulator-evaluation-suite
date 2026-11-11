"""get-object-attributes-size-etag."""

from __future__ import annotations

import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "get-object-attributes-size-etag"
GROUP = 'data_integrity'
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
        # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "project", "Value": "sim2real"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes reports ObjectSize and ETag consistent with the stored object."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "attrs.bin"
    body = b"attribute-payload" * 64
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    attrs = s3.get_object_attributes(
        Bucket=bucket, Key=key, ObjectAttributes=["ETag", "ObjectSize", "StorageClass"]
    )

    assert attrs["ObjectSize"] == len(body), f"expected ObjectSize {len(body)}, got {attrs.get('ObjectSize')}"
    assert attrs["ETag"].strip('"') == hashlib.md5(body).hexdigest(), (
        f"GetObjectAttributes ETag disagrees with the object MD5: {attrs['ETag']!r}"
    )
    assert attrs.get("StorageClass", "STANDARD") == "STANDARD", (
        f"expected StorageClass STANDARD (or omitted), got {attrs.get('StorageClass')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
