"""restore-object-on-standard-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "restore-object-on-standard-rejected"
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
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "restore-object-on-standard-rejected"}]},
    )
    return name


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject on a STANDARD object fails with InvalidObjectState and its exact message and starts
    no restore, while the same call on a GLACIER object in the same bucket starts an ongoing restore."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)

    # Positive control: RestoreObject against an archived object is accepted.
    archived_key = "archived.bin"
    s3.put_object(Bucket=name, Key=archived_key, Body=b"cold-data", StorageClass="GLACIER")
    s3.restore_object(
        Bucket=name, Key=archived_key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Standard"}},
    )
    archived_head = s3.head_object(Bucket=name, Key=archived_key)
    restore_hdr = archived_head.get("Restore", "")
    assert 'ongoing-request="true"' in restore_hdr, (
        f"expected an ongoing-restore marker after RestoreObject on an archived object, got {restore_hdr!r}"
    )

    # Negative: the identical call against a STANDARD (never-archived) object is rejected.
    key = "not-archived.txt"
    s3.put_object(Bucket=name, Key=key, Body=b"x")

    refusal = _error(lambda: s3.restore_object(
        Bucket=name, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Standard"}},
    ))
    assert refusal == ("InvalidObjectState", "Restore is not allowed for the object's current storage class"), (
        f"expected InvalidObjectState restoring a STANDARD object, got {refusal!r}"
    )

    # the object is untouched and has no Restore header
    head = s3.head_object(Bucket=name, Key=key)
    assert "Restore" not in head, f"no restore should be in progress, got {head.get('Restore')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
