"""list-object-versions-pagination-markers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-object-versions-pagination-markers"
GROUP = 'listing'
SERVICES = ['s3']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectVersions paginates via NextKeyMarker/NextVersionIdMarker and enumerates every
    version exactly once."""
    s3 = ctx.client("s3")
    name = _create_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    expected: set[tuple[str, str]] = set()
    for key in ("mv/a.txt", "mv/b.txt"):
        for _ in range(2):
            vid = s3.put_object(Bucket=name, Key=key, Body=b"x")["VersionId"]
            expected.add((key, vid))

    seen: list[tuple[str, str]] = []
    key_marker = ""
    version_marker = ""
    pages = 0
    while True:
        kwargs = {"Bucket": name, "Prefix": "mv/", "MaxKeys": 1}
        if key_marker:
            kwargs["KeyMarker"] = key_marker
        if version_marker:
            kwargs["VersionIdMarker"] = version_marker
        page = s3.list_object_versions(**kwargs)
        pages += 1
        page_versions = page.get("Versions", [])
        assert len(page_versions) <= 1, (
            f"MaxKeys=1 was not honored: page {pages} returned {len(page_versions)} versions"
        )
        seen.extend((v["Key"], v["VersionId"]) for v in page_versions)
        if not page.get("IsTruncated"):
            break
        key_marker = page["NextKeyMarker"]
        version_marker = page.get("NextVersionIdMarker", "")
        assert key_marker, "IsTruncated=True must be paired with NextKeyMarker"
        assert pages < 20, "version pagination did not terminate"

    assert pages == len(expected), (
        f"MaxKeys=1 across {len(expected)} versions should force {len(expected)} pages, got {pages}"
    )
    assert len(seen) == len(set(seen)), f"pagination returned duplicate versions: {seen}"
    assert set(seen) == expected, f"expected {expected}, got {set(seen)}"


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
    # us-east-1 is the one region S3 requires you to omit LocationConstraint for; this is
    # the API's default-region quirk, not a resource pinned to a region.
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
