"""object-annotation-not-found-errors."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-annotation-not-found-errors"
GROUP = 'annotations'
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
    # us-east-1 is CreateBucket's API default: passing a LocationConstraint for it is rejected.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetObjectAnnotation returns NoSuchBucket, NoSuchKey, or NoSuchAnnotation
    depending on which resource in the chain (bucket / object / annotation) is
    missing; once the chain is complete, the identical call succeeds."""
    s3 = ctx.client("s3")
    fake_bucket = ctx.unique_name("sim2real-behav-annot-nobkt-")
    code1, message1 = _err(
        lambda: s3.get_object_annotation(Bucket=fake_bucket, Key="whatever.txt", AnnotationName="note")
    )
    assert code1 == "NoSuchBucket", f"expected NoSuchBucket, got {code1}"
    assert message1 == "The specified bucket does not exist", f"unexpected NoSuchBucket message: {message1!r}"

    bucket = _new_bucket(ctx, s3)
    code2, message2 = _err(
        lambda: s3.get_object_annotation(Bucket=bucket, Key="never-created.txt", AnnotationName="note")
    )
    assert code2 == "NoSuchKey", f"expected NoSuchKey, got {code2}"
    assert message2 == "The specified key does not exist.", f"unexpected NoSuchKey message: {message2!r}"

    key = "annot-get-target.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"data")
    annotation_name = "never-set"
    code3, message3 = _err(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=annotation_name)
    )
    assert code3 == "NoSuchAnnotation", f"expected NoSuchAnnotation, got {code3}"
    assert message3 == NO_SUCH_ANNOTATION_MESSAGE, f"unexpected NoSuchAnnotation message: {message3!r}"

    # Positive control: once bucket, key and annotation all exist, the identical call
    # (same bucket, key and annotation name) succeeds and returns what was put.
    payload = b"now-set"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=annotation_name, AnnotationPayload=payload)
    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=annotation_name)
    got_payload = got["AnnotationPayload"].read()
    assert got_payload == payload, f"expected {payload!r} once the chain is complete, got {got_payload!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
