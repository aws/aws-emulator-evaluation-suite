"""copy-object-not-in-active-tier-rejected."""

from __future__ import annotations
import os
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "copy-object-not-in-active-tier-rejected"
GROUP = 'storage_classes'
SERVICES = ['s3']

_COPY_ARCHIVED = ("InvalidObjectState", "Operation is not valid for the source object's storage class")
_HEAD_ABSENT = ("404", 'Not Found')


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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject from an archived, unrestored GLACIER object fails with InvalidObjectState and its exact
    message and creates no destination, while the same copy from a STANDARD source is byte-identical."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)

    # Positive control: CopyObject from a STANDARD-tier source succeeds byte-for-byte.
    std_src = "standard-src.bin"
    std_body = os.urandom(1024)
    s3.put_object(Bucket=name, Key=std_src, Body=std_body)
    s3.copy_object(Bucket=name, Key="dst-from-standard.bin", CopySource={"Bucket": name, "Key": std_src})
    copied_body = s3.get_object(Bucket=name, Key="dst-from-standard.bin")["Body"].read()
    assert copied_body == std_body, "positive-control copy from a STANDARD source must be byte-identical"

    src = "archived-src.bin"
    s3.put_object(Bucket=name, Key=src, Body=os.urandom(1024), StorageClass="GLACIER")

    refusal = _error(
        lambda: s3.copy_object(Bucket=name, Key="dst.bin", CopySource={"Bucket": name, "Key": src})
    )
    assert refusal == _COPY_ARCHIVED, f"expected {_COPY_ARCHIVED!r}, got {refusal!r}"

    dst = _error(lambda: s3.head_object(Bucket=name, Key="dst.bin"))
    assert dst == _HEAD_ABSENT, f"expected the copy destination absent {_HEAD_ABSENT!r}, got {dst!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
