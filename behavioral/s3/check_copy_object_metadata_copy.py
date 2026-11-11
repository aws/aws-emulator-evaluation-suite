"""copy-object-metadata-copy."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "copy-object-metadata-copy"
GROUP = 'copy'
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject with MetadataDirective=COPY preserves source metadata."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(
        Bucket=bucket,
        Key="cp-src.txt",
        Body=b"data",
        Metadata={"keep-me": "yes"},
    )
    s3.copy_object(
        Bucket=bucket,
        Key="cp-dst.txt",
        CopySource={"Bucket": bucket, "Key": "cp-src.txt"},
        MetadataDirective="COPY",
    )
    head_dst = s3.head_object(Bucket=bucket, Key="cp-dst.txt")
    assert head_dst["Metadata"] == {"keep-me": "yes"}, (
        f"expected COPY to preserve exactly the source metadata, got {head_dst['Metadata']!r}"
    )
    head_src = s3.head_object(Bucket=bucket, Key="cp-src.txt")
    assert head_src["Metadata"] == {"keep-me": "yes"}, (
        f"expected the source object's own metadata to be unaffected by the copy, got {head_src['Metadata']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
