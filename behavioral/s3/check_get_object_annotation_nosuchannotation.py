"""get-object-annotation-nosuchannotation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-annotation-nosuchannotation"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAnnotation returns NoSuchAnnotation when the named annotation does
    not exist on an otherwise perfectly valid object, rather than an empty payload
    or a generic error."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "annotated-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # A real annotation exists, but under a different name.
    s3.put_object_annotation(
        Bucket=bucket, Key=key, AnnotationName="present-annotation", AnnotationPayload=b"hi"
    )

    # Sanity: fetching the real one works.
    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="present-annotation")
    payload = got["AnnotationPayload"].read()
    assert payload == b"hi", f"positive control: expected annotation payload b'hi', got {payload!r}"

    err = _error(
        lambda: s3.get_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="absent-annotation"
        )
    )
    assert err.get("Code") == "NoSuchAnnotation", (
        f"expected NoSuchAnnotation for an annotation name that was never set, got {err!r}"
    )
    assert err.get("Message") == "The specified annotation does not exist.", err.get("Message")


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected NoSuchAnnotation, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
