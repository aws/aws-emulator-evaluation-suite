"""object-storage-class-reflected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-storage-class-reflected"
GROUP = 'object-crud'
SERVICES = ['s3']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StorageClass is persisted per-object: STANDARD_IA surfaces on HeadObject/ListObjectsV2,
    while STANDARD is omitted from HeadObject."""
    s3 = ctx.client("s3")
    name = _create_bucket(ctx, s3)
    s3.put_object(Bucket=name, Key="ia.txt", Body=b"x", StorageClass="STANDARD_IA")
    s3.put_object(Bucket=name, Key="std.txt", Body=b"x")

    ia_head = s3.head_object(Bucket=name, Key="ia.txt")
    assert ia_head.get("StorageClass") == "STANDARD_IA", (
        f"expected STANDARD_IA, got {ia_head.get('StorageClass')!r}"
    )

    std_head = s3.head_object(Bucket=name, Key="std.txt")
    assert "StorageClass" not in std_head, (
        f"HeadObject must omit StorageClass for STANDARD objects, got {std_head.get('StorageClass')!r}"
    )

    listed = {o["Key"]: o["StorageClass"] for o in s3.list_objects_v2(Bucket=name)["Contents"]}
    assert listed == {"ia.txt": "STANDARD_IA", "std.txt": "STANDARD"}, (
        f"unexpected listing storage classes: {listed}"
    )


def _empty_bucket(s3, bucket):
    """Remove every object, version, delete marker, and in-flight multipart upload so the
    bucket can actually be deleted."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                try:
                    s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                try:
                    s3.delete_object(Bucket=bucket, Key=o["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                try:
                    s3.abort_multipart_upload(
                        Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "NoSuchBucket",
                        "NoSuchKey",
                        "NoSuchUpload",
                    ):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _delete_bucket_force(s3, bucket):
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_bucket(ctx, s3, name=None, **kwargs):
    """Create a uniquely-named bucket with the right LocationConstraint, register
    empty+delete teardown, and return its name."""
    name = name or ctx.unique_name("sim2real-behav-s3fid-")
    params = dict(kwargs)
    if ctx.region and ctx.region != "us-east-1":
        cfg = params.pop("CreateBucketConfiguration", {})
        cfg.setdefault("LocationConstraint", ctx.region)
        params["CreateBucketConfiguration"] = cfg
    s3.create_bucket(Bucket=name, **params)
    ctx.on_cleanup(lambda: _delete_bucket_force(s3, name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
