"""public-access-block."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "public-access-block"
GROUP = 'acls_policies'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPublicAccessBlock returns each of the four settings exactly as PutPublicAccessBlock set them;
    the configuration is not all-True, so a target that ignores the PUT and serves the default fails."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    config = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True,
    }
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=config)
    resp = s3.get_public_access_block(Bucket=bucket)
    got = resp["PublicAccessBlockConfiguration"]
    for key, val in config.items():
        assert got[key] == val, f"{key}: expected {val}, got {got[key]}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
