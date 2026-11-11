"""cors-configuration-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "cors-configuration-roundtrip"
GROUP = 'cors'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketCors then GetBucketCors returns the same rules."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    cors_config = {
        "CORSRules": [
            {
                "AllowedHeaders": ["Authorization", "Content-Type"],
                "AllowedMethods": ["GET", "PUT"],
                "AllowedOrigins": ["https://example.com"],
                "ExposeHeaders": ["x-amz-request-id"],
                "MaxAgeSeconds": 3600,
            }
        ]
    }
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration=cors_config)
    resp = s3.get_bucket_cors(Bucket=bucket)
    rules = resp.get("CORSRules", [])
    assert len(rules) == 1, f"expected 1 CORS rule, got {rules}"
    rule = rules[0]
    assert set(rule["AllowedMethods"]) == {"GET", "PUT"}, f"AllowedMethods: {rule['AllowedMethods']}"
    assert rule["AllowedOrigins"] == ["https://example.com"], f"AllowedOrigins: {rule['AllowedOrigins']}"
    assert rule["MaxAgeSeconds"] == 3600, f"MaxAgeSeconds: {rule['MaxAgeSeconds']}"
    assert set(rule["AllowedHeaders"]) == {"Authorization", "Content-Type"}, (
        f"AllowedHeaders: {rule['AllowedHeaders']}"
    )
    assert rule["ExposeHeaders"] == ["x-amz-request-id"], f"ExposeHeaders: {rule['ExposeHeaders']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
