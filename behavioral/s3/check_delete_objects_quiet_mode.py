"""delete-objects-quiet-mode."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "delete-objects-quiet-mode"
GROUP = 'lifecycle'
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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects with Quiet=True omits the per-key Deleted entries while still removing every key."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    keys = ["q/1.txt", "q/2.txt", "q/3.txt"]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")

    before = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])}
    assert before == set(keys), f"expected all keys present before delete, got {before}"

    resp = s3.delete_objects(
        Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys], "Quiet": True}
    )

    assert not resp.get("Deleted"), f"Quiet=True must suppress Deleted entries, got {resp.get('Deleted')}"
    assert not resp.get("Errors"), f"unexpected errors: {resp.get('Errors')}"
    remaining = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert remaining == [], f"all keys should be gone, still present: {[o['Key'] for o in remaining]}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
