"""list-object-annotations-invalid-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-object-annotations-invalid-prefix"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListObjectAnnotations rejects a malformed AnnotationPrefix with InvalidPrefix,
    and returns NoSuchBucket/NoSuchKey for missing resources rather than an empty
    listing."""
    s3 = ctx.client("s3")

    # 1. Nonexistent bucket -> NoSuchBucket.
    missing_bucket = ctx.unique_name("sim2real-nobucket-")
    err_bucket = _client_error(
        lambda: s3.list_object_annotations(Bucket=missing_bucket, Key="whatever")
    )
    assert err_bucket.get("Code") == "NoSuchBucket", f"expected NoSuchBucket, got {err_bucket!r}"
    assert err_bucket.get("Message") == "The specified bucket does not exist", err_bucket

    bucket = _create_bucket(ctx)

    # 2. Existing bucket, missing key -> NoSuchKey.
    err_key = _client_error(
        lambda: s3.list_object_annotations(Bucket=bucket, Key="does-not-exist.bin")
    )
    assert err_key.get("Code") == "NoSuchKey", f"expected NoSuchKey, got {err_key!r}"
    assert err_key.get("Message") == "The specified key does not exist.", err_key

    # 3. Existing object, malformed prefix -> InvalidPrefix. AnnotationPrefix is a
    #    request-level query filter (not an annotation name being created), so real
    #    S3 does not apply the annotation-name validation rules (reserved "aws-"
    #    prefix, character set, etc.) to it -- a prefix like "aws-reserved-prefix"
    #    is a perfectly legal (if non-matching) filter value. What real S3 does
    #    reject is a filter value that cannot possibly match any legal annotation
    #    name, such as one containing a NUL byte -- and it does so with the
    #    dedicated "InvalidPrefix" error code, not the generic "InvalidArgument".
    key = "annotated.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    s3.put_object_annotation(
        Bucket=bucket, Key=key, AnnotationName="real-annotation", AnnotationPayload=b"1"
    )

    err_prefix = _client_error(
        lambda: s3.list_object_annotations(
            Bucket=bucket, Key=key, AnnotationPrefix="bad\x00prefix"
        )
    )
    assert err_prefix.get("Code") == "InvalidPrefix", f"expected InvalidPrefix, got {err_prefix!r}"
    assert err_prefix.get("Message") == "The annotation prefix you have provided is invalid.", err_prefix

    # A valid prefix must still work and find the real annotation.
    listing = s3.list_object_annotations(Bucket=bucket, Key=key, AnnotationPrefix="real-")
    names = [a["AnnotationName"] for a in listing.get("Annotations", [])]
    assert "real-annotation" in names, f"expected 'real-annotation' in {names}"


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
