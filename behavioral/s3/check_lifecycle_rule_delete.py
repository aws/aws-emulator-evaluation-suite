"""lifecycle-rule-delete."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "lifecycle-rule-delete"
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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteBucketLifecycle removes lifecycle config."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    config = {
        "Rules": [
            {
                "ID": "tmp-rule",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 1},
            }
        ]
    }
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=config)
    got = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    assert got["Rules"][0]["ID"] == "tmp-rule", f"expected rule 'tmp-rule' before deletion, got {got.get('Rules')}"

    s3.delete_bucket_lifecycle(Bucket=bucket)
    err = _client_error(lambda: s3.get_bucket_lifecycle_configuration(Bucket=bucket))
    assert err.get("Code") == "NoSuchLifecycleConfiguration", f"expected NoSuchLifecycleConfiguration after deletion, got {err!r}"
    assert err.get("Message") == "The lifecycle configuration does not exist", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
