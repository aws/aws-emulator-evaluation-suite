"""object-annotation-nonexistent-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-annotation-nonexistent-version-rejected"
GROUP = "object_annotations"
SERVICES = ["s3"]

_NO_SUCH_VERSION = ("NoSuchVersion", "The specified version does not exist.")


def _expect_error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises, since the
    call is one AWS refuses."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A VersionId that once existed but was permanently deleted is refused NoSuchVersion by
    every annotation operation (Put, Get, List, Delete), not treated as the current version or
    as a missing annotation."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-annnover-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    key = "reports/probe.txt"
    annotation_name = "review-note"
    v1 = s3.put_object(Bucket=bucket, Key=key, Body=b"version one")["VersionId"]
    s3.put_object_annotation(
        Bucket=bucket, Key=key, AnnotationName=annotation_name, AnnotationPayload=b"on version one"
    )

    # Permanently remove v1: a DeleteObject naming a VersionId erases that version outright,
    # leaving no object behind it (no new version, no delete marker).
    s3.delete_object(Bucket=bucket, Key=key, VersionId=v1)

    put_err = _expect_error_code(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=annotation_name,
            AnnotationPayload=b"new", VersionId=v1,
        )
    )
    assert put_err == _NO_SUCH_VERSION, f"PutObjectAnnotation on a deleted version: expected {_NO_SUCH_VERSION!r}, got {put_err!r}"

    get_err = _expect_error_code(
        lambda: s3.get_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=annotation_name, VersionId=v1
        )
    )
    assert get_err == _NO_SUCH_VERSION, f"GetObjectAnnotation on a deleted version: expected {_NO_SUCH_VERSION!r}, got {get_err!r}"

    list_err = _expect_error_code(
        lambda: s3.list_object_annotations(Bucket=bucket, Key=key, VersionId=v1)
    )
    assert list_err == _NO_SUCH_VERSION, f"ListObjectAnnotations on a deleted version: expected {_NO_SUCH_VERSION!r}, got {list_err!r}"

    delete_err = _expect_error_code(
        lambda: s3.delete_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=annotation_name, VersionId=v1
        )
    )
    assert delete_err == _NO_SUCH_VERSION, f"DeleteObjectAnnotation on a deleted version: expected {_NO_SUCH_VERSION!r}, got {delete_err!r}"

    # Positive control: a fresh version in the same key still takes annotations normally.
    v2 = s3.put_object(Bucket=bucket, Key=key, Body=b"version two")["VersionId"]
    put2 = s3.put_object_annotation(
        Bucket=bucket, Key=key, AnnotationName=annotation_name, AnnotationPayload=b"on version two"
    )
    assert put2["ObjectVersionId"] == v2, (
        f"expected the control annotation to attach to the current version {v2!r}, "
        f"got {put2['ObjectVersionId']!r}"
    )
    got2 = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=annotation_name)
    assert got2["AnnotationPayload"].read() == b"on version two", (
        "expected the control's annotation to read back the payload it just wrote"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
