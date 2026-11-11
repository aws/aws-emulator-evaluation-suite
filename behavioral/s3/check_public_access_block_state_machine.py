"""public-access-block-state-machine."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "public-access-block-state-machine"
GROUP = 'bucket-subresources'
SERVICES = ['s3']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Block Public Access is all-on by default, is fully settable, and after
    DeletePublicAccessBlock Get yields NoSuchPublicAccessBlockConfiguration."""
    s3 = ctx.client("s3")
    name = _create_bucket(ctx, s3)
    fields = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

    default_cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    assert all(default_cfg[f] is True for f in fields), (
        f"new buckets must default to Block Public Access all-on, got {default_cfg!r}"
    )

    s3.put_public_access_block(
        Bucket=name, PublicAccessBlockConfiguration={f: False for f in fields}
    )
    off = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    assert all(off[f] is False for f in fields), f"all-off config not persisted: {off!r}"

    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        },
    )
    mixed = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    assert (mixed["BlockPublicAcls"], mixed["IgnorePublicAcls"]) == (True, False), (
        f"mixed config not persisted: {mixed!r}"
    )
    assert (mixed["BlockPublicPolicy"], mixed["RestrictPublicBuckets"]) == (True, False), (
        f"mixed config not persisted: {mixed!r}"
    )

    s3.delete_public_access_block(Bucket=name)
    code = _error(lambda: s3.get_public_access_block(Bucket=name))
    assert code == ("NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found"), (
        f"expected NoSuchPublicAccessBlockConfiguration, got {code!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
