"""restore-archived-object-active-tier-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-archived-object-active-tier-error"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject on a never-archived STANDARD object returns InvalidObjectState and starts no
    restore; the same call on an archived GLACIER sibling succeeds, so the rejection is specific
    to storage class."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "active-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello-active-tier")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # Sanity: the object really is in the Standard (active) storage tier.
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass", "STANDARD") == "STANDARD", (
        f"expected STANDARD storage class for a freshly-PUT object, got {head.get('StorageClass')!r}"
    )

    refusal = _error(
        lambda: s3.restore_object(Bucket=bucket, Key=key, RestoreRequest={"Days": 1})
    )
    assert refusal == ("InvalidObjectState", "Restore is not allowed for the object's current storage class"), (
        f"expected InvalidObjectState restoring an already-active object, got {refusal!r}"
    )

    # Effect-absent: the rejected call left no restore job in progress.
    head_after = s3.head_object(Bucket=bucket, Key=key)
    assert "Restore" not in head_after, (
        f"no restore should be in progress after a rejected RestoreObject, got {head_after.get('Restore')!r}"
    )

    # Positive control: the identical shape of call succeeds against an object that
    # IS archived, closing the gap where a target that unconditionally rejects every
    # RestoreObject call would otherwise pass this check.
    archived_key = "archived-control.txt"
    s3.put_object(Bucket=bucket, Key=archived_key, Body=b"cold-control", StorageClass="GLACIER")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=archived_key))
    try:
        s3.restore_object(
            Bucket=bucket,
            Key=archived_key,
            RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Standard"}},
        )
    except ClientError as exc:
        raise AssertionError(
            f"RestoreObject on an archived (GLACIER) object should succeed, got {exc}"
        ) from exc


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup():
        try:
            resp = s3.list_object_versions(Bucket=name)
            for v in resp.get("Versions", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
            for m in resp.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=m["Key"], VersionId=m["VersionId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=name):
                for u in page.get("Uploads", []):
                    s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
