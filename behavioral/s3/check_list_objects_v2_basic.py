"""list-objects-v2-basic."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-objects-v2-basic"
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
        # us-east-1 is CreateBucket's implicit default; passing a LocationConstraint for it
        # is itself an error, so the literal is a protocol quirk, not a pinned resource region.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectsV2 returns uploaded keys with correct metadata."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    keys = ["a/1.txt", "a/2.txt", "b/1.txt"]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=f"content-{k}")
    resp = s3.list_objects_v2(Bucket=bucket)
    got_keys = sorted(obj["Key"] for obj in resp.get("Contents", []))
    assert got_keys == sorted(keys), f"expected {sorted(keys)}, got {got_keys}"
    assert resp["KeyCount"] == 3, f"expected KeyCount 3, got {resp['KeyCount']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
