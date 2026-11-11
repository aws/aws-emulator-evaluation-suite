"""etag-is-md5-for-single-put."""

from __future__ import annotations
import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "etag-is-md5-for-single-put"
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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ETag for a non-multipart PUT is the hex MD5 of the body (quoted), and that
    holds on an independent read back, not just the PutObject response."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"etag-test-body-sim2real"
    key = "etag-test"
    resp = s3.put_object(Bucket=bucket, Key=key, Body=body)
    expected_md5 = hashlib.md5(body).hexdigest()
    # ETag is returned with surrounding quotes
    put_etag = resp["ETag"].strip('"')
    assert put_etag == expected_md5, f"PutObject ETag {put_etag} != expected MD5 {expected_md5}"

    head = s3.head_object(Bucket=bucket, Key=key)
    head_etag = head["ETag"].strip('"')
    assert head_etag == expected_md5, (
        f"HeadObject ETag {head_etag} != expected MD5 {expected_md5} on independent read"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
