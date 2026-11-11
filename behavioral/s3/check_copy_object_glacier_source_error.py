"""copy-object-glacier-source-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-glacier-source-error"
GROUP = "error-semantics"
SERVICES = ["s3"]

_COPY_ARCHIVED = ("InvalidObjectState", "Operation is not valid for the source object's storage class")
_HEAD_ABSENT = ("404", 'Not Found')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject from an unrestored GLACIER source is refused with InvalidObjectState and its exact
    message and creates no destination, while the same copy from a STANDARD source is byte-identical."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    # Positive control: CopyObject from a STANDARD-tier source works end to end.
    standard_key = "standard-src.bin"
    standard_body = b"hot-data-copies-fine"
    standard_dst = "copy-of-standard-src.bin"
    s3.put_object(Bucket=bucket, Key=standard_key, Body=standard_body)
    s3.copy_object(
        Bucket=bucket, Key=standard_dst, CopySource={"Bucket": bucket, "Key": standard_key}
    )
    copied_body = s3.get_object(Bucket=bucket, Key=standard_dst)["Body"].read()
    assert copied_body == standard_body, (
        f"positive control failed: expected {standard_body!r} from the STANDARD-tier copy, "
        f"got {copied_body!r}"
    )

    src_key = "glacier-src.bin"
    dst_key = "copy-of-glacier-src.bin"

    s3.put_object(Bucket=bucket, Key=src_key, Body=b"cold-data", StorageClass="GLACIER")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=src_key))

    head = s3.head_object(Bucket=bucket, Key=src_key)
    assert head.get("StorageClass") == "GLACIER", (
        f"expected the source to land in GLACIER, got {head.get('StorageClass')!r}"
    )
    # Never restored: no x-amz-restore header should be present yet.
    assert "Restore" not in head, f"expected no Restore header before any restore request, got {head.get('Restore')!r}"

    refusal = _error(
        lambda: s3.copy_object(
            Bucket=bucket, Key=dst_key, CopySource={"Bucket": bucket, "Key": src_key}
        )
    )
    assert refusal == _COPY_ARCHIVED, (
        f"expected {_COPY_ARCHIVED!r} copying an un-restored GLACIER source, got {refusal!r}"
    )

    # Independent read at the destination: the rejected copy must not have created it.
    dst = _error(lambda: s3.head_object(Bucket=bucket, Key=dst_key))
    assert dst == _HEAD_ABSENT, (
        f"expected the copy destination absent {_HEAD_ABSENT!r} after the rejected copy, got {dst!r}"
    )


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
