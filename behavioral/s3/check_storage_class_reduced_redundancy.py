"""storage-class-reduced-redundancy."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "storage-class-reduced-redundancy"
GROUP = 'storage_classes'
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
    # us-east-1 is the only region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Objects stored with REDUCED_REDUNDANCY storage class report it back on both
    HeadObject and ListObjectsV2 — two independent reads, neither the PutObject that wrote it."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(
        Bucket=bucket,
        Key="rr.txt",
        Body=b"reduced",
        StorageClass="REDUCED_REDUNDANCY",
    )

    head = s3.head_object(Bucket=bucket, Key="rr.txt")
    assert head.get("StorageClass") == "REDUCED_REDUNDANCY", (
        f"expected REDUCED_REDUNDANCY on HeadObject, got {head.get('StorageClass')!r}"
    )

    resp = s3.list_objects_v2(Bucket=bucket, Prefix="rr.txt")
    contents = resp.get("Contents", [])
    assert len(contents) == 1, f"expected exactly one listed object, got {len(contents)}"
    sc = contents[0].get("StorageClass")
    assert sc == "REDUCED_REDUNDANCY", f"expected REDUCED_REDUNDANCY on ListObjectsV2, got {sc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
