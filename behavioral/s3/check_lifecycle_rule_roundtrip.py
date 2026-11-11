"""lifecycle-rule-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "lifecycle-rule-roundtrip"
GROUP = 'lifecycle_rules'
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
        # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketLifecycleConfiguration then GetBucketLifecycleConfiguration round-trips."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    config = {
        "Rules": [
            {
                "ID": "sim2real-expire-30d",
                "Status": "Enabled",
                "Filter": {"Prefix": "logs/"},
                "Expiration": {"Days": 30},
            }
        ]
    }
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=config)
    resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    rules = resp.get("Rules", [])
    assert len(rules) == 1, f"expected exactly 1 rule, got {len(rules)}: {rules!r}"
    assert rules[0]["ID"] == "sim2real-expire-30d", f"expected rule ID 'sim2real-expire-30d', got {rules[0].get('ID')!r}"
    assert rules[0]["Status"] == "Enabled", f"expected Status 'Enabled', got {rules[0].get('Status')!r}"
    assert rules[0]["Expiration"]["Days"] == 30, f"expected Expiration.Days == 30, got {rules[0].get('Expiration')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
