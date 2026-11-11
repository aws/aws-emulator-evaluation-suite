"""s3-strong-read-after-write."""

from __future__ import annotations
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "s3-strong-read-after-write"
GROUP = 'consistency'
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
        # us-east-1 is S3's original region and CreateBucket rejects an explicit
        # LocationConstraint there; every other region requires one.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A brand-new key is immediately GETtable and visible in ListObjectsV2, and an
    immediate overwrite of that key is immediately GETtable too (strong read-after-write,
    for both first-write and overwrite)."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = f"raw/{uuid.uuid4().hex}.txt"
    body = b"strong-read-after-write-sim2real"

    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # Immediate GET — no retry/poll: S3 is strongly consistent for new objects.
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == body, f"expected immediate read-your-write, got {got!r}"

    resp = s3.list_objects_v2(Bucket=bucket, Prefix="raw/")
    listed = {o["Key"] for o in resp.get("Contents", [])}
    assert key in listed, f"new key {key} not immediately visible in ListObjectsV2: {listed}"

    overwrite_body = b"strong-read-after-overwrite-sim2real"
    s3.put_object(Bucket=bucket, Key=key, Body=overwrite_body)

    # Immediate GET after overwriting an *existing* key — no retry/poll: S3 has been
    # strongly consistent for overwrites (not just first-writes) since December 2020.
    got_after_overwrite = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got_after_overwrite == overwrite_body, (
        f"expected immediate read-your-overwrite, got {got_after_overwrite!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
