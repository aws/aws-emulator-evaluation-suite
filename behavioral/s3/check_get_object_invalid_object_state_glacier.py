"""get-object-invalid-object-state-glacier."""

from __future__ import annotations
import os
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-object-invalid-object-state-glacier"
GROUP = 'storage_classes'
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject on an unrestored GLACIER object fails with InvalidObjectState, and still does right
    after RestoreObject (the restore is async); a STANDARD object in the same bucket reads fine."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)

    control_key = "active.bin"
    control_body = os.urandom(64)
    s3.put_object(Bucket=name, Key=control_key, Body=control_body)
    control = s3.get_object(Bucket=name, Key=control_key)
    assert control["Body"].read() == control_body, "positive control: GetObject on a STANDARD object must succeed"

    key = "archived.bin"
    s3.put_object(Bucket=name, Key=key, Body=os.urandom(1024), StorageClass="GLACIER")

    err = _client_error(lambda: s3.get_object(Bucket=name, Key=key))
    assert err.get("Code") == "InvalidObjectState", f"expected InvalidObjectState, got {err!r}"
    assert err.get("Message") == "The operation is not valid for the object's storage class", err

    s3.restore_object(Bucket=name, Key=key, RestoreRequest={"Days": 1})

    err2 = _client_error(lambda: s3.get_object(Bucket=name, Key=key))
    assert err2.get("Code") == "InvalidObjectState", (
        f"expected InvalidObjectState immediately after RestoreObject (restore is "
        f"async and not yet complete), got {err2!r}"
    )
    assert err2.get("Message") == "The operation is not valid for the object's storage class", err2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
