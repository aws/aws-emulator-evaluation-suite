"""range-read-byte-range."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "range-read-byte-range"
GROUP = 'range_reads'
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject with Range='bytes=0-4' returns the first 5 bytes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"0123456789ABCDEF"
    s3.put_object(Bucket=bucket, Key="range.bin", Body=body)
    resp = s3.get_object(Bucket=bucket, Key="range.bin", Range="bytes=0-4")
    got = resp["Body"].read()
    assert got == b"01234", f"expected b'01234', got {got!r}"
    assert resp["ContentLength"] == 5, f"expected ContentLength 5, got {resp['ContentLength']}"
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 206, f"expected HTTP 206 Partial Content, got {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
