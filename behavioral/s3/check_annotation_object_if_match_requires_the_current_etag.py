"""annotation-object-if-match-requires-the-current-etag."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "annotation-object-if-match-requires-the-current-etag"
GROUP = "conditional-write"
SERVICES = ["s3"]

_STALE_OBJECT_IF_MATCH = ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObjectAnnotation and DeleteObjectAnnotation refuse an ObjectIfMatch that names a prior
    ETag once the object has since changed, leaving the annotation as it was."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-annot-ifmatch-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "catalog-entry.json"
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    name_kept = "price-tier"
    name_other = "discount-code"
    payload_kept = b"tier-standard"
    payload_rejected = b"code-never-written"
    payload_accepted = b"code-autumn-sale"

    stale_etag = s3.put_object(Bucket=bucket, Key=key, Body=b'{"sku":"A1"}')["ETag"]
    current_etag = s3.put_object(Bucket=bucket, Key=key, Body=b'{"sku":"A1","rev":2}')["ETag"]
    assert current_etag != stale_etag, f"overwriting the object must change its ETag, still {current_etag!r}"

    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_kept, AnnotationPayload=payload_kept)

    expect_error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=name_other,
            AnnotationPayload=payload_rejected, ObjectIfMatch=stale_etag,
        ),
        *_STALE_OBJECT_IF_MATCH,
    )
    expect_error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_other),
        "NoSuchAnnotation", "The specified annotation does not exist.",
    )
    kept_untouched = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_kept)
    kept_payload = kept_untouched["AnnotationPayload"].read()
    assert kept_payload == payload_kept, (
        f"the refused Put must not disturb {name_kept!r}, expected {payload_kept!r}, got {kept_payload!r}"
    )

    # The control: the same call with the object's current ETag succeeds.
    s3.put_object_annotation(
        Bucket=bucket, Key=key, AnnotationName=name_other,
        AnnotationPayload=payload_accepted, ObjectIfMatch=current_etag,
    )
    accepted = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_other)
    accepted_payload = accepted["AnnotationPayload"].read()
    assert accepted_payload == payload_accepted, (
        f"a Put with the current ETag should have written {payload_accepted!r}, got {accepted_payload!r}"
    )

    # The same precondition on Delete: a stale ObjectIfMatch is refused and leaves it in place.
    expect_error(
        lambda: s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_kept, ObjectIfMatch=stale_etag),
        *_STALE_OBJECT_IF_MATCH,
    )
    still_there = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_kept)
    still_there_payload = still_there["AnnotationPayload"].read()
    assert still_there_payload == payload_kept, (
        f"the refused Delete must leave {name_kept!r} intact, expected {payload_kept!r}, got "
        f"{still_there_payload!r}"
    )

    # The control: the same Delete with the current ETag succeeds.
    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_kept, ObjectIfMatch=current_etag)
    expect_error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name_kept),
        "NoSuchAnnotation", "The specified annotation does not exist.",
    )


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises a ClientError with exactly this (code, message); an unexpected
    success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected code {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected ({code!r}, {message!r}) but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
