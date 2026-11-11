"""get-object-invalid-state-archived."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-invalid-state-archived"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject on an archived (GLACIER), not-yet-restored object returns
    InvalidObjectState rather than the object body -- but only for the archived
    object; an ordinary STANDARD object in the same bucket must still read fine."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    # Positive control: GetObject on a normal object in this bucket must succeed,
    # so a target that rejects every read cannot pass by accident.
    live_key = "live-object.bin"
    live_body = b"warm-data"
    s3.put_object(Bucket=bucket, Key=live_key, Body=live_body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=live_key))
    control = s3.get_object(Bucket=bucket, Key=live_key)
    assert control["Body"].read() == live_body, "positive control: a STANDARD object must read back unchanged"

    key = "archived-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"deep-freeze", StorageClass="GLACIER")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("StorageClass") == "GLACIER", f"expected StorageClass GLACIER, got {head.get('StorageClass')!r}"
    assert "Restore" not in head, f"expected no Restore header before any restore request, got {head.get('Restore')!r}"

    err = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert err.get("Code") == "InvalidObjectState", (
        f"expected InvalidObjectState reading an un-restored GLACIER object, got {err!r}"
    )
    assert err.get("Message") == "The operation is not valid for the object's storage class", err


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

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


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
