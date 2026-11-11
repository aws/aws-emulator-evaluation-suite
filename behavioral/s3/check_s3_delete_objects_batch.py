"""s3-delete-objects-batch."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "s3-delete-objects-batch"
GROUP = 'lifecycle'
SERVICES = ['s3']

ERR_NO_SUCH_KEY = "NoSuchKey"

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


def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects (batch) removes all listed keys; response lists them; GETs then 404."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    keys = [f"batch/obj-{i}.txt" for i in range(5)]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=f"content-{k}")

    resp = s3.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": k} for k in keys], "Quiet": False},
    )
    deleted = {d["Key"] for d in resp.get("Deleted", [])}
    assert deleted == set(keys), f"expected all keys in Deleted, got {deleted}"
    assert not resp.get("Errors"), f"expected no per-key errors, got {resp.get('Errors')}"

    for k in keys:
        err = _err(lambda k=k: s3.get_object(Bucket=bucket, Key=k), f"GetObject of deleted {k}")
        assert err.get("Code") == ERR_NO_SUCH_KEY, f"expected {ERR_NO_SUCH_KEY} for deleted {k}, got {err!r}"
        assert err.get("Message") == "The specified key does not exist.", err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
