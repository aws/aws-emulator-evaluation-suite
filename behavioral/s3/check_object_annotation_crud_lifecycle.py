"""object-annotation-crud-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "object-annotation-crud-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]
NO_SUCH_ANNOTATION_MESSAGE = 'The specified annotation does not exist.'


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put -> Get -> List -> Delete an object annotation; list reflects the current set exactly."""
    s3 = ctx.client("s3")
    if not hasattr(s3, "put_object_annotation"):
        raise AssertionError("boto3 s3 client lacks put_object_annotation (S3 object annotations API not available)")

    bucket = _new_bucket(ctx, s3)
    key = "docs/report.json"
    s3.put_object(Bucket=bucket, Key=key, Body=b'{"hello":"world"}')

    ann_name = "project.notes"
    payload = b"first annotation payload"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=ann_name, AnnotationPayload=payload)

    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=ann_name)
    got_payload = got["AnnotationPayload"].read()
    assert got_payload == payload, f"expected payload {payload!r}, got {got_payload!r}"
    assert got["ContentLength"] == len(payload), f"expected ContentLength {len(payload)}, got {got['ContentLength']}"

    listed = s3.list_object_annotations(Bucket=bucket, Key=key)
    names = [a["AnnotationName"] for a in listed.get("Annotations", [])]
    assert names == [ann_name], f"expected only {ann_name!r}, got {names}"
    assert listed["AnnotationCount"] == 1, f"expected AnnotationCount 1, got {listed['AnnotationCount']}"

    # Overwrite in place: PutObjectAnnotation replaces the payload for the same name.
    new_payload = b"updated annotation payload, longer than before"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=ann_name, AnnotationPayload=new_payload)
    got2 = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=ann_name)
    got2_payload = got2["AnnotationPayload"].read()
    assert got2_payload == new_payload, f"expected overwritten payload {new_payload!r}, got {got2_payload!r}"
    assert got2["ContentLength"] == len(new_payload), (
        f"expected ContentLength {len(new_payload)} after overwrite, got {got2['ContentLength']}"
    )

    # A second, distinct annotation is additive, not a replacement.
    other_name = "project.status"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=other_name, AnnotationPayload=b"open")
    listed2 = s3.list_object_annotations(Bucket=bucket, Key=key)
    names2 = sorted(a["AnnotationName"] for a in listed2.get("Annotations", []))
    assert names2 == sorted([ann_name, other_name]), f"expected both annotations, got {names2}"
    assert listed2["AnnotationCount"] == 2, f"expected AnnotationCount 2, got {listed2['AnnotationCount']}"

    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=ann_name)
    listed3 = s3.list_object_annotations(Bucket=bucket, Key=key)
    names3 = [a["AnnotationName"] for a in listed3.get("Annotations", [])]
    assert names3 == [other_name], f"expected only {other_name!r} to remain, got {names3}"
    assert listed3["AnnotationCount"] == 1, f"expected AnnotationCount 1 after partial delete, got {listed3['AnnotationCount']}"

    code, message = _error(lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=ann_name))
    assert code == "NoSuchAnnotation", f"expected NoSuchAnnotation, got {code}"
    assert message == NO_SUCH_ANNOTATION_MESSAGE, f"unexpected NoSuchAnnotation message: {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-s3-behav-").lower()
    kwargs = {"Bucket": name}
    # us-east-1 is the CreateBucket API's implicit default: passing a LocationConstraint of
    # "us-east-1" is itself rejected, so the literal here is the region-pinned exception, not a hardcode.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=name)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
