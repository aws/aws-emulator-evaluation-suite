"""restore-object-duplicate-in-progress-rejected."""

from __future__ import annotations
import os
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "restore-object-duplicate-in-progress-rejected"
GROUP = 'storage_classes'
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


def _err(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second RestoreObject while the first Standard-tier restore of a GLACIER object is ongoing fails
    with RestoreAlreadyInProgress and its exact message, and the original restore stays ongoing."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "restore-duplicate-obj.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=os.urandom(1024), StorageClass="GLACIER")

    s3.restore_object(
        Bucket=bucket,
        Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Standard"}},
    )

    # Positive control: an independent read confirms the first restore actually put the object
    # into an in-progress state -- without this, a rejected second call would be indistinguishable
    # from a target that rejects EVERY RestoreObject call regardless of state.
    before = s3.head_object(Bucket=bucket, Key=key).get("Restore", "")
    assert before == 'ongoing-request="true"', f"expected a restore in progress before the duplicate attempt, got Restore={before!r}"

    code, message = _err(
        lambda: s3.restore_object(
            Bucket=bucket,
            Key=key,
            RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Standard"}},
        )
    )
    assert code == "RestoreAlreadyInProgress", f"expected RestoreAlreadyInProgress for a duplicate restore, got {code}"
    assert message == "Object restore is already in progress", message

    # Effect absent: an independent read at the destination, through a DIFFERENT operation than
    # either RestoreObject call, shows the rejected duplicate left the in-flight restore
    # untouched -- it neither reset, completed, nor otherwise disturbed the single job the first
    # call started.
    after = s3.head_object(Bucket=bucket, Key=key).get("Restore", "")
    assert after == 'ongoing-request="true"', f"expected the original restore to still be in progress after the rejected duplicate, got Restore={after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
