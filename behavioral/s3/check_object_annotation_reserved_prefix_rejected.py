"""object-annotation-reserved-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-annotation-reserved-prefix-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]
NO_SUCH_ANNOTATION_MESSAGE = 'The specified annotation does not exist.'
INVALID_ANNOTATION_MESSAGE = "Your annotation name cannot start with 'aws' or 's3'."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutObjectAnnotation rejects names starting with 'aws' or 's3' with InvalidAnnotation and its
    exact message and stores nothing under them, while an ordinary name round-trips its payload and is
    NoSuchAnnotation after delete."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-annotneg-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "object-for-invalid-annotation.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    code, message = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="aws:reserved-name", AnnotationPayload=b"payload"
        )
    )
    assert code == "InvalidAnnotation", f"expected InvalidAnnotation for 'aws:'-prefixed name, got {code}"
    assert message == INVALID_ANNOTATION_MESSAGE, f"unexpected InvalidAnnotation message: {message!r}"
    # The name itself is invalid, not merely absent: GetObjectAnnotation enforces the same
    # reserved-prefix validation up front and rejects it identically, rather than answering
    # NoSuchAnnotation for a name nothing was ever stored under.
    absent_code, absent_message = _get_error(s3, bucket, key, "aws:reserved-name")
    assert absent_code == "InvalidAnnotation", (
        f"get on the rejected 'aws:'-prefixed name should re-reject it as InvalidAnnotation, got {absent_code!r}"
    )
    assert absent_message == INVALID_ANNOTATION_MESSAGE, f"unexpected InvalidAnnotation message: {absent_message!r}"

    code2, message2 = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="s3:internal-name", AnnotationPayload=b"payload"
        )
    )
    assert code2 == "InvalidAnnotation", f"expected InvalidAnnotation for 's3:'-prefixed name, got {code2}"
    assert message2 == INVALID_ANNOTATION_MESSAGE, f"unexpected InvalidAnnotation message: {message2!r}"
    absent_code2, absent_message2 = _get_error(s3, bucket, key, "s3:internal-name")
    assert absent_code2 == "InvalidAnnotation", (
        f"get on the rejected 's3:'-prefixed name should re-reject it as InvalidAnnotation, got {absent_code2!r}"
    )
    assert absent_message2 == INVALID_ANNOTATION_MESSAGE, f"unexpected InvalidAnnotation message: {absent_message2!r}"

    # A name unrelated to the reserved prefixes must be accepted, round-trip on an
    # independent read, and be fully removable.
    accepted_name = "team-priority-label"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=accepted_name, AnnotationPayload=b"payload")
    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=accepted_name)
    assert got["AnnotationPayload"].read() == b"payload", "accepted annotation must round-trip its payload"

    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=accepted_name)
    gone_code, gone_message = _get_error(s3, bucket, key, accepted_name)
    assert gone_code == "NoSuchAnnotation", f"deleted annotation must no longer be readable, got {gone_code!r}"
    assert gone_message == NO_SUCH_ANNOTATION_MESSAGE, f"unexpected NoSuchAnnotation message: {gone_message!r}"


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


def _get_error(s3, bucket: str, key: str, annotation_name: str):
    return _error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=annotation_name)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
