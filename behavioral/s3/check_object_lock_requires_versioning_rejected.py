"""object-lock-requires-versioning-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-lock-requires-versioning-rejected"
GROUP = 'object_lock'
SERVICES = ['s3']
VERSIONING_REQUIRED_MESSAGE = "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration"
NO_LOCK_CONFIGURATION_MESSAGE = 'Object Lock configuration does not exist for this bucket'


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


def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Object Lock requires versioning: PutObjectLockConfiguration on a non-versioned
    bucket must fail with InvalidBucketState, nothing is persisted by the rejected call,
    and enabling versioning lifts the rejection so the identical call now succeeds."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)
    assert "Status" not in s3.get_bucket_versioning(Bucket=name), "precondition: bucket must be unversioned"
    lock_cfg = {"ObjectLockEnabled": "Enabled"}

    code, message = _err(lambda: s3.put_object_lock_configuration(Bucket=name, ObjectLockConfiguration=lock_cfg))
    assert code == "InvalidBucketState", f"expected InvalidBucketState on an unversioned bucket, got {code!r}"
    assert message == VERSIONING_REQUIRED_MESSAGE, f"unexpected InvalidBucketState message: {message!r}"

    # nothing may have been persisted by the rejected call
    code, message = _err(lambda: s3.get_object_lock_configuration(Bucket=name))
    assert code == "ObjectLockConfigurationNotFoundError", (
        f"expected ObjectLockConfigurationNotFoundError, got {code!r}"
    )
    assert message == NO_LOCK_CONFIGURATION_MESSAGE, f"unexpected ObjectLockConfigurationNotFoundError message: {message!r}"

    # restore: enabling versioning lifts the rejection -- the identical call now succeeds
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object_lock_configuration(Bucket=name, ObjectLockConfiguration=lock_cfg)

    got = s3.get_object_lock_configuration(Bucket=name)["ObjectLockConfiguration"]
    assert got["ObjectLockEnabled"] == "Enabled", (
        f"expected the identical PutObjectLockConfiguration call to succeed once versioning is "
        f"enabled, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
