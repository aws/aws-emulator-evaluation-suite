"""checksum-sha256."""

from __future__ import annotations

import base64
import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "checksum-sha256"
GROUP = 'data_integrity'
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
    """PutObject with ChecksumAlgorithm=SHA256 returns the true SHA256 of the body on GET."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"sha256-test-payload"
    expected = base64.b64encode(hashlib.sha256(body).digest()).decode()
    s3.put_object(
        Bucket=bucket,
        Key="sha256-obj",
        Body=body,
        ChecksumAlgorithm="SHA256",
    )
    resp = s3.get_object(Bucket=bucket, Key="sha256-obj", ChecksumMode="ENABLED")
    sha = resp.get("ChecksumSHA256")
    assert sha == expected, f"ChecksumSHA256 mismatch: expected {expected!r} (real SHA256 of body), got {sha!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
