"""list-objects-v1-marker-pagination."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-objects-v1-marker-pagination"
GROUP = 'pagination'
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
        # us-east-1 is CreateBucket's own default region and rejects an explicit
        # LocationConstraint for it; every other region requires one.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjects (v1) paginates by Marker=last-returned-key and reports IsTruncated correctly."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    keys = [f"v1/{i:02d}.txt" for i in range(5)]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")

    seen: list[str] = []
    marker = ""
    pages = 0
    while True:
        page = s3.list_objects(Bucket=bucket, Prefix="v1/", MaxKeys=2, Marker=marker)
        pages += 1
        batch = [o["Key"] for o in page.get("Contents", [])]
        seen.extend(batch)
        assert len(batch) <= 2, f"MaxKeys=2 violated, got {len(batch)} keys"
        if not page.get("IsTruncated"):
            break
        marker = batch[-1]
        assert pages < 10, "pagination did not terminate"

    assert seen == keys, f"expected {keys} in lexicographic order, got {seen}"
    assert pages == 3, f"expected 3 pages for 5 keys at MaxKeys=2, got {pages}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
