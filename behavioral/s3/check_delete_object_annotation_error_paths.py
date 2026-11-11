"""delete-object-annotation-error-paths."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-object-annotation-error-paths"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjectAnnotation returns NoSuchBucket for a missing bucket and
    NoSuchKey for a missing object, rather than treating either as an
    already-satisfied delete."""
    s3 = ctx.client("s3")

    # 1. Nonexistent bucket -> NoSuchBucket.
    missing_bucket = ctx.unique_name("sim2real-nobucket-")
    code_bucket = _error(
        lambda: s3.delete_object_annotation(
            Bucket=missing_bucket, Key="whatever", AnnotationName="ann"
        )
    )
    assert code_bucket == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"expected NoSuchBucket with AWS's exact message, got {code_bucket!r}"
    )

    bucket = _create_bucket(ctx)

    # 2. Existing bucket, missing object -> NoSuchKey.
    code_key = _error(
        lambda: s3.delete_object_annotation(
            Bucket=bucket, Key="does-not-exist.bin", AnnotationName="ann"
        )
    )
    assert code_key == ("NoSuchKey", "The specified key does not exist."), (
        f"expected NoSuchKey with AWS's exact message, got {code_key!r}"
    )

    # Sanity: deleting a real annotation on a real object succeeds.
    key = "annotated-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName="ann", AnnotationPayload=b"1")
    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName="ann")

    code_gone = _error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="ann")
    )
    assert code_gone == ("NoSuchAnnotation", "The specified annotation does not exist."), (
        f"expected NoSuchAnnotation with AWS's exact message, got {code_gone!r}"
    )


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    # us-east-1 is CreateBucket's API default: passing a LocationConstraint for it is rejected.
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
    """Call fn(); return the ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
