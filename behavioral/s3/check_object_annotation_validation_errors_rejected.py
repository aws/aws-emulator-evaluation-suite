"""object-annotation-validation-errors-rejected."""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-annotation-validation-errors-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]
NO_SUCH_ANNOTATION_MESSAGE = 'The specified annotation does not exist.'
INVALID_ANNOTATION_MESSAGE = "Your annotation name cannot start with 'aws' or 's3'."
NAME_TOO_LONG_MESSAGE = 'Your annotation name is too long.'
LIMIT_EXCEEDED_MESSAGE = 'The object annotation count (1001) exceeds the limit (1000).'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectAnnotation rejects a too-long name (AnnotationNameTooLong), a reserved prefix
    (InvalidAnnotation) and the annotation past the per-version cap (AnnotationLimitExceeded) with exact
    messages and stores none of them, while a valid annotation round-trips its payload."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key = "annotated-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"parent-object-body")

    # --- Positive control: a valid annotation is created and round-trips exactly. ---
    valid_name = "pipeline.stage-1_result"
    valid_payload = b"{\"label\": \"cat\", \"confidence\": 0.97}"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=valid_name, AnnotationPayload=valid_payload)
    fetched = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=valid_name)
    assert fetched["AnnotationPayload"].read() == valid_payload

    # --- AnnotationNameTooLong: name over 512 bytes is rejected. ---
    too_long_name = "n" * 513
    code, message = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=too_long_name, AnnotationPayload=b"x"
        )
    )
    assert code == "AnnotationNameTooLong", f"expected AnnotationNameTooLong, got {code!r}"
    assert message == NAME_TOO_LONG_MESSAGE, f"unexpected AnnotationNameTooLong message: {message!r}"
    # GetObjectAnnotation validates the name (same rule as PutObjectAnnotation) before it
    # would even look up whether an annotation exists, so an over-length name is rejected
    # with the same validation error rather than NoSuchAnnotation -- either way, no
    # annotation was ever created under this name.
    not_found_code, not_found_message = _error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=too_long_name)
    )
    assert (not_found_code, not_found_message) == (code, message), (
        f"expected the too-long name to be rejected identically by GetObjectAnnotation "
        f"({code!r}, {message!r}), got ({not_found_code!r}, {not_found_message!r})"
    )

    # --- InvalidAnnotationName: reserved "aws"/"s3" prefixes are rejected. ---
    reserved_name = "aws-reserved-annotation"
    code, message = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=reserved_name, AnnotationPayload=b"x"
        )
    )
    assert code == "InvalidAnnotation", f"expected InvalidAnnotation, got {code!r}"
    assert message == INVALID_ANNOTATION_MESSAGE, f"unexpected InvalidAnnotation message: {message!r}"
    # Same name-validation-before-lookup behavior as above: the reserved-prefix name is
    # rejected identically by GetObjectAnnotation, confirming no annotation was created.
    not_found_code, not_found_message = _error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=reserved_name)
    )
    assert (not_found_code, not_found_message) == (code, message), (
        f"expected the reserved-prefix name to be rejected identically by GetObjectAnnotation "
        f"({code!r}, {message!r}), got ({not_found_code!r}, {not_found_message!r})"
    )

    # --- AnnotationLimitExceeded: an object version caps out at 1000 annotations. ---
    # We already created 1 (valid_name); fill up to the 1000-annotation ceiling concurrently.
    remaining = 1000 - 1
    names = [f"bulk-annotation-{i:04d}" for i in range(remaining)]

    def _put_one(name: str) -> None:
        # Filling to the 1000-annotation cap concurrently against a single key hammers real S3's
        # per-object write path hard enough to produce not just the named "SlowDown" throttle but
        # also other transient contention errors with no fixed code. None of that is the terminal
        # AnnotationLimitExceeded rejection under test below, so every ClientError encountered while
        # filling is retried with jittered backoff rather than treated as a check failure.
        attempt = 0
        while True:
            try:
                s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, AnnotationPayload=b"1")
                return
            except ClientError:
                if attempt >= 14:
                    raise
                attempt += 1
                delay = min(0.25 * (1.6**attempt), 4.0)
                time.sleep(delay + random.uniform(0, delay * 0.5))

    with ThreadPoolExecutor(max_workers=24) as pool:
        for _ in pool.map(_put_one, names):
            pass

    code, message = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="one-too-many", AnnotationPayload=b"x"
        )
    )
    assert code == "AnnotationLimitExceeded", f"expected AnnotationLimitExceeded, got {code!r}"
    assert message == LIMIT_EXCEEDED_MESSAGE, f"unexpected AnnotationLimitExceeded message: {message!r}"
    not_found_code, not_found_message = _error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="one-too-many")
    )
    assert not_found_code == "NoSuchAnnotation", f"expected NoSuchAnnotation, got {not_found_code!r}"
    assert not_found_message == NO_SUCH_ANNOTATION_MESSAGE, (
        f"unexpected NoSuchAnnotation message: {not_found_message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(s3, bucket: str, region: str) -> None:
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=bucket)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
