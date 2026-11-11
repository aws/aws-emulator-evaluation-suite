"""put-object-annotation-limits."""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-annotation-limits"
GROUP = "error-semantics"
SERVICES = ["s3"]

_MAX_ANNOTATIONS_PER_OBJECT = 1000


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectAnnotation rejects too-long, invalid-character and reserved-prefix names with exact
    errors, and on an object holding 1,000 annotations rejects one more with AnnotationLimitExceeded,
    evicting none; after one is deleted, a new one fits."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "annotated-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # Name too long (> 512 bytes, otherwise made of valid characters).
    code_too_long = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="a" * 513, AnnotationPayload=b"x"
        )
    )
    assert code_too_long == ("AnnotationNameTooLong", "Your annotation name is too long."), (
        f"expected AnnotationNameTooLong for a 513-byte name, got {code_too_long!r}"
    )

    # Invalid character in the name. Real S3 rejects any structurally-invalid
    # annotation name (bad characters, reserved prefix, etc.) with the single
    # "InvalidAnnotation" code, not a name-specific "InvalidAnnotationName" code.
    code_invalid_char = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="bad!name", AnnotationPayload=b"x"
        )
    )
    assert code_invalid_char == ("InvalidAnnotation", "Your annotation name contains invalid characters."), (
        f"expected InvalidAnnotation for a name with disallowed characters, got {code_invalid_char!r}"
    )

    # Reserved prefix.
    code_reserved = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="aws-reserved", AnnotationPayload=b"x"
        )
    )
    assert code_reserved == ("InvalidAnnotation", "Your annotation name cannot start with 'aws' or 's3'."), (
        f"expected InvalidAnnotation for a name starting with the reserved 'aws' "
        f"prefix, got {code_reserved!r}"
    )

    # Fill the object up to the per-object annotation cap. Concurrent writes to one object's
    # annotation set draw SlowDown, bare 5xx/429 and contention errors, none of which is the cap
    # this check grades, so every fill write retries any ClientError with jittered backoff. The
    # cap itself is graded afterwards, sequentially, once the count has settled at 1,000.
    _MAX_ATTEMPTS = 20

    def _is_retryable(exc: ClientError, code: str) -> bool:
        # Every ClientError raised while filling is transient/contention noise
        # from concurrently writing to the same object's annotation set --
        # see the comment above for why retrying unconditionally here is
        # correct and does not mask the check's real assertions.
        return True

    def _put_one(i: int) -> str | None:
        name = f"ann-{i:04d}"
        last_code = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                s3.put_object_annotation(
                    Bucket=bucket,
                    Key=key,
                    AnnotationName=name,
                    AnnotationPayload=b"1",
                )
                return None
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                last_code = code
                if not _is_retryable(exc, code):
                    return code
            if attempt == _MAX_ATTEMPTS - 1:
                # Last attempt already made; no point sleeping further before
                # giving up -- avoids wasting a full backoff interval per item.
                break
            base_delay = min(0.25 * (1.6 ** attempt), 3.0)
            time.sleep(base_delay + random.uniform(0, base_delay * 0.5))
        return last_code

    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = [pool.submit(_put_one, i) for i in range(_MAX_ANNOTATIONS_PER_OBJECT)]
        failures = [f.result() for f in as_completed(futures) if f.result() is not None]
    assert not failures, f"unexpected errors filling up to the annotation cap: {failures[:5]}"

    # Poll briefly for the count to settle. AnnotationCount is page-scoped (like KeyCount), so the
    # page is sized to the cap and the returned annotations are counted.
    listing = None
    actual_count = -1
    delay = 1.0
    for _ in range(10):
        listing = s3.list_object_annotations(
            Bucket=bucket, Key=key, MaxAnnotationResults=_MAX_ANNOTATIONS_PER_OBJECT
        )
        actual_count = len(listing.get("Annotations", []))
        if actual_count == _MAX_ANNOTATIONS_PER_OBJECT and not listing.get("IsTruncated"):
            break
        time.sleep(delay)
        delay = min(delay * 1.5, 3.0)
    assert actual_count == _MAX_ANNOTATIONS_PER_OBJECT, (
        f"expected {_MAX_ANNOTATIONS_PER_OBJECT} annotations, got {actual_count}"
    )

    # One more annotation beyond the cap must be rejected.
    code_over_cap = _error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName="one-too-many", AnnotationPayload=b"1"
        )
    )
    assert code_over_cap == ("AnnotationLimitExceeded", (
        f"The object annotation count ({_MAX_ANNOTATIONS_PER_OBJECT + 1}) exceeds the limit "
        f"({_MAX_ANNOTATIONS_PER_OBJECT})."
    )), (
        f"expected AnnotationLimitExceeded at the 1,001st annotation, got {code_over_cap!r}"
    )

    # The rejection must have had no effect: still exactly 1,000 annotations, the
    # rejected name absent, and every annotation the fill loop wrote still present
    # -- i.e. the cap rejects the write outright rather than silently evicting an
    # older annotation to make room, which is the claim this check exists to test.
    after_reject = s3.list_object_annotations(
        Bucket=bucket, Key=key, MaxAnnotationResults=_MAX_ANNOTATIONS_PER_OBJECT
    )
    names_after_reject = {a["AnnotationName"] for a in after_reject.get("Annotations", [])}
    assert len(names_after_reject) == _MAX_ANNOTATIONS_PER_OBJECT, (
        f"expected {_MAX_ANNOTATIONS_PER_OBJECT} annotations after the rejected write, "
        f"got {len(names_after_reject)}"
    )
    assert "one-too-many" not in names_after_reject, (
        "rejected annotation 'one-too-many' must not appear on the object"
    )
    expected_names = {f"ann-{i:04d}" for i in range(_MAX_ANNOTATIONS_PER_OBJECT)}
    assert names_after_reject == expected_names, (
        "the rejected write must not have evicted an existing annotation to make room"
    )

    # Restore: free exactly one slot, then the identical call must now succeed --
    # proving the prior rejection was the cap being enforced, not the object or the
    # operation being broken.
    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName="ann-0000")
    code_after_free = _error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="ann-0000")
    )
    assert code_after_free == ("NoSuchAnnotation", "The specified annotation does not exist."), (
        f"expected NoSuchAnnotation for the deleted slot, got {code_after_free!r}"
    )

    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName="one-too-many", AnnotationPayload=b"1")
    got_restored = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName="one-too-many")
    assert got_restored["AnnotationPayload"].read() == b"1", (
        "expected 'one-too-many' to be readable back after the cap freed up a slot"
    )


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
