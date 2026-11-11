"""delete-object-annotation-missing-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "delete-object-annotation-missing-rejected"
GROUP = 'annotations'
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
    return name


def _err(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised.

    An unexpected SUCCESS raises, so an over-permissive target fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteObjectAnnotation on a never-created key fails with NoSuchKey and the key stays absent,
    while deleting a real annotation on a real object succeeds and then reads NoSuchAnnotation."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)

    key = "annotated.txt"
    try:
        s3.put_object(Bucket=name, Key=key, Body=b"payload")
        s3.put_object_annotation(Bucket=name, Key=key, AnnotationName="sim2real-note", AnnotationPayload=b"1")
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks the object-annotations API: {exc}") from exc
    s3.delete_object_annotation(Bucket=name, Key=key, AnnotationName="sim2real-note")
    code_gone = _err(
        lambda: s3.get_object_annotation(Bucket=name, Key=key, AnnotationName="sim2real-note")
    )
    assert code_gone == ("NoSuchAnnotation", "The specified annotation does not exist."), (
        f"expected the deleted annotation to read back NoSuchAnnotation, got {code_gone!r}"
    )

    # Deleting a never-set annotation name on an existing object is an idempotent success, so the
    # must-fail boundary is a missing parent object.
    try:
        code = _err(
            lambda: s3.delete_object_annotation(
                Bucket=name, Key="never-created.txt", AnnotationName="sim2real-note"
            )
        )
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks DeleteObjectAnnotation support: {exc}") from exc
    assert code == ("NoSuchKey", "The specified key does not exist."), (
        f"expected NoSuchKey deleting an annotation on a nonexistent object, got {code!r}"
    )

    # The rejected delete must have had no side effect: the key it named still does not exist.
    code_head = _err(lambda: s3.head_object(Bucket=name, Key="never-created.txt"))
    # A HEAD response has no body, so botocore fills Message from the HTTP reason phrase.
    assert code_head == ("404", "Not Found"), f"expected the never-created key to still be absent, got {code_head!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
