"""object-annotation-full-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-annotation-full-crud-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]
NO_SUCH_ANNOTATION_MESSAGE = 'The specified annotation does not exist.'


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObjectAnnotation creates a named annotation visible via Get/List; a second Put to the same
    name overwrites in place rather than appending, a distinct name is additive, and Delete removes
    each name independently, leaving the rest intact until none remain."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-annot-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "annotated-object.json"
    s3.put_object(Bucket=bucket, Key=key, Body=b'{"source":"sensor"}')
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    name_a = "ml-inference-label"
    payload = b'{"label":"cat","confidence":0.97}'
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_a, AnnotationPayload=payload)

    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_a)
    got_payload = got["AnnotationPayload"].read()
    assert got_payload == payload, f"expected payload {payload!r}, got {got_payload!r}"

    listed = s3.list_object_annotations(Bucket=bucket, Key=key)
    names = [a["AnnotationName"] for a in listed.get("Annotations", [])]
    assert name_a in names, f"expected {name_a!r} in {names}"
    assert listed["AnnotationCount"] == 1, f"expected AnnotationCount 1, got {listed['AnnotationCount']}"

    # A second Put under the same name overwrites in place; it must not create a second entry.
    overwrite_payload = b'{"label":"dog","confidence":0.61}'
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_a, AnnotationPayload=overwrite_payload)
    got_overwrite = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_a)
    got_overwrite_payload = got_overwrite["AnnotationPayload"].read()
    assert got_overwrite_payload == overwrite_payload, (
        f"expected overwrite to read back {overwrite_payload!r}, got {got_overwrite_payload!r}"
    )
    listed_overwrite = s3.list_object_annotations(Bucket=bucket, Key=key)
    assert listed_overwrite["AnnotationCount"] == 1, (
        f"overwriting an existing name must not add an entry, got AnnotationCount "
        f"{listed_overwrite['AnnotationCount']}"
    )

    # A distinct name is additive, not a replacement of the first.
    name_b = "ml-inference-score"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_b, AnnotationPayload=b"0.61")
    listed_both = s3.list_object_annotations(Bucket=bucket, Key=key)
    names_both = sorted(a["AnnotationName"] for a in listed_both.get("Annotations", []))
    assert names_both == sorted([name_a, name_b]), f"expected both names present, got {names_both}"
    assert listed_both["AnnotationCount"] == 2, f"expected AnnotationCount 2, got {listed_both['AnnotationCount']}"

    # Deleting one name must leave the other untouched.
    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_a)

    code, message = _error(lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_a))
    assert code == "NoSuchAnnotation", f"expected NoSuchAnnotation after delete, got {code}"
    assert message == NO_SUCH_ANNOTATION_MESSAGE, f"unexpected NoSuchAnnotation message: {message!r}"

    listed_one_left = s3.list_object_annotations(Bucket=bucket, Key=key)
    names_one_left = [a["AnnotationName"] for a in listed_one_left.get("Annotations", [])]
    assert names_one_left == [name_b], f"expected only {name_b!r} to remain, got {names_one_left}"
    assert listed_one_left["AnnotationCount"] == 1, (
        f"expected AnnotationCount 1 after deleting one of two, got {listed_one_left['AnnotationCount']}"
    )

    # Delete the remaining annotation; the object returns to having none.
    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_b)

    listed_after = s3.list_object_annotations(Bucket=bucket, Key=key)
    assert listed_after["AnnotationCount"] == 0, f"expected AnnotationCount 0, got {listed_after['AnnotationCount']}"
    names_after = [a["AnnotationName"] for a in listed_after.get("Annotations", [])]
    assert name_b not in names_after, f"annotation still listed after delete: {names_after}"


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
