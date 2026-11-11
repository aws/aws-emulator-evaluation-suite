"""copy-object-cross-bucket."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "copy-object-cross-bucket"
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
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject across buckets works, and leaves the source untouched."""
    s3 = ctx.client("s3")
    src_bucket = _new_bucket(ctx, s3)
    dst_bucket = _new_bucket(ctx, s3)
    body = b"cross-bucket-copy"
    s3.put_object(Bucket=src_bucket, Key="origin.bin", Body=body)
    s3.copy_object(
        Bucket=dst_bucket,
        Key="copied.bin",
        CopySource={"Bucket": src_bucket, "Key": "origin.bin"},
    )
    got = s3.get_object(Bucket=dst_bucket, Key="copied.bin")["Body"].read()
    assert got == body, f"cross-bucket copy did not preserve bytes: expected {body!r}, got {got!r}"

    src_still = s3.get_object(Bucket=src_bucket, Key="origin.bin")["Body"].read()
    assert src_still == body, (
        f"CopyObject must not remove or alter the source object: expected {body!r}, got {src_still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
