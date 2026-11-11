"""object-annotation-roundtrip."""

from __future__ import annotations
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-annotation-roundtrip"
GROUP = 'object_annotations'
SERVICES = ['s3']
NO_SUCH_ANNOTATION_MESSAGE = 'The specified annotation does not exist.'


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
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObjectAnnotation entries appear via GetObjectAnnotation/ListObjectAnnotations and are
    removable via DeleteObjectAnnotation."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "annotated.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"base-object")

    try:
        s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="sim2real-note", AnnotationPayload=b"hello-annotation"
        )
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks PutObjectAnnotation support: {exc}") from exc

    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="sim2real-note")
    payload = got["AnnotationPayload"].read()
    assert payload == b"hello-annotation", f"expected b'hello-annotation', got {payload!r}"

    listed = s3.list_object_annotations(Bucket=bucket, Key=key)
    names = set()
    for a in listed.get("Annotations", []) or []:
        names.add(a.get("AnnotationName") if isinstance(a, dict) else a)
    assert "sim2real-note" in names, f"expected annotation in ListObjectAnnotations, got {listed}"
    assert listed.get("AnnotationCount") == 1, f"expected AnnotationCount == 1, got {listed}"

    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName="sim2real-note")
    code, message = _err(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="sim2real-note")
    )
    assert code == "NoSuchAnnotation", f"expected NoSuchAnnotation after delete, got {code}"
    assert message == NO_SUCH_ANNOTATION_MESSAGE, f"unexpected NoSuchAnnotation message: {message!r}"

    listed2 = s3.list_object_annotations(Bucket=bucket, Key=key)
    names2 = set()
    for a in listed2.get("Annotations", []) or []:
        names2.add(a.get("AnnotationName") if isinstance(a, dict) else a)
    assert "sim2real-note" not in names2, f"expected annotation gone from list, got {listed2}"
    assert listed2.get("AnnotationCount") == 0, f"expected AnnotationCount == 0, got {listed2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
