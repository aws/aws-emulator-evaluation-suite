"""bucket-ownership-controls-roundtrip."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-ownership-controls-roundtrip"
GROUP = 'acls_policies'
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
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint on CreateBucket
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Buckets default to ObjectOwnership=BucketOwnerEnforced; the control can be switched and
    deleted, after which Get yields OwnershipControlsNotFoundError."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    initial = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
    assert initial[0]["ObjectOwnership"] == "BucketOwnerEnforced", (
        f"expected the BucketOwnerEnforced default, got {initial!r}"
    )

    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
    )
    rules = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
    assert rules[0]["ObjectOwnership"] == "ObjectWriter", f"ownership switch not persisted: {rules!r}"

    s3.delete_bucket_ownership_controls(Bucket=bucket)
    code, message = _error(lambda: s3.get_bucket_ownership_controls(Bucket=bucket))
    assert code == "OwnershipControlsNotFoundError", f"expected OwnershipControlsNotFoundError, got {code!r}"
    assert message == "The bucket ownership controls were not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
