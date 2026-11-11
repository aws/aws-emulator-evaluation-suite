"""list-objects-v2-prefix."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-objects-v2-prefix"
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
        # us-east-1 is S3's implicit default region; CreateBucket rejects an explicit
        # LocationConstraint there (only other regions require one).
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectsV2 with Prefix filters correctly."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="photos/2024/jan.jpg", Body=b"j")
    s3.put_object(Bucket=bucket, Key="photos/2024/feb.jpg", Body=b"f")
    s3.put_object(Bucket=bucket, Key="docs/readme.md", Body=b"r")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix="photos/")
    got_keys = sorted(obj["Key"] for obj in resp.get("Contents", []))
    expected_keys = ["photos/2024/feb.jpg", "photos/2024/jan.jpg"]
    assert got_keys == expected_keys, f"expected {expected_keys}, got {got_keys}"
    assert resp["KeyCount"] == 2, f"expected KeyCount 2, got {resp['KeyCount']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
