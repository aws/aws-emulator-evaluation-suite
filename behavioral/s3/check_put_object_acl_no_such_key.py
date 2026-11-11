"""put-object-acl-no-such-key."""

from __future__ import annotations
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "put-object-acl-no-such-key"
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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutObjectAcl on a key that was never written fails with NoSuchKey and its exact message on an
    ObjectWriter bucket (where ACL writes are enabled), and HeadObject on that key answers 404."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
    )

    # Positive control: PutObjectAcl on a key that does exist must succeed, so the
    # NoSuchKey below is attributable to the missing key and not to ACL writes being
    # rejected outright for this bucket.
    control_key = "exists.txt"
    s3.put_object(Bucket=bucket, Key=control_key, Body=b"acl-positive-control")
    s3.put_object_acl(Bucket=bucket, Key=control_key, ACL="private")

    missing_key = "never-existed.txt"
    code = _error(lambda: s3.put_object_acl(Bucket=bucket, Key=missing_key, ACL="private"))
    assert code == ("NoSuchKey", "The specified key does not exist."), f"expected NoSuchKey, got {code}"

    # Effect absent, via an independent read on a different operation: the key really
    # isn't there, not merely rejected by PutObjectAcl specifically.
    head_code = _error(lambda: s3.head_object(Bucket=bucket, Key=missing_key))[0]
    assert head_code == "404", f"expected HeadObject 404 for a key that was never written, got {head_code}"

    # Restore: once the same key is created, the identical PutObjectAcl call succeeds.
    s3.put_object(Bucket=bucket, Key=missing_key, Body=b"now-it-exists")
    s3.put_object_acl(Bucket=bucket, Key=missing_key, ACL="private")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
