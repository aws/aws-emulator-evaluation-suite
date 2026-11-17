"""list-object-annotations-max-annotation-results-over-one-thousand-rejected."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-object-annotations-max-annotation-results-over-one-thousand-rejected"
GROUP = "object-annotation"
SERVICES = ["s3"]

_MAX_ALLOWED = 1000


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListObjectAnnotations accepts MaxAnnotationResults up to 1,000 but rejects 1,001 with
    InvalidArgument, leaving the listing otherwise unaffected."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "annotated-object.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName="boundary", AnnotationPayload=b"v")

    control = s3.list_object_annotations(Bucket=bucket, Key=key, MaxAnnotationResults=_MAX_ALLOWED)
    assert [a["AnnotationName"] for a in control["Annotations"]] == ["boundary"], (
        f"MaxAnnotationResults={_MAX_ALLOWED} must be accepted and list the one annotation "
        f"written, got {control['Annotations']!r}"
    )

    code, message = _error(
        lambda: s3.list_object_annotations(
            Bucket=bucket, Key=key, MaxAnnotationResults=_MAX_ALLOWED + 1
        )
    )
    assert code == "InvalidArgument", (
        f"expected InvalidArgument for MaxAnnotationResults={_MAX_ALLOWED + 1}, got {code!r}: "
        f"{message!r}"
    )
    assert message == (
        f"Argument max-annotation-results must be an integer between 1 and {_MAX_ALLOWED}"
    ), f"unexpected InvalidArgument message for an over-range MaxAnnotationResults: {message!r}"

    after = s3.list_object_annotations(Bucket=bucket, Key=key, MaxAnnotationResults=_MAX_ALLOWED)
    assert [a["AnnotationName"] for a in after["Annotations"]] == ["boundary"], (
        f"the rejected over-range request must not have changed the object's annotation list, "
        f"got {after['Annotations']!r}"
    )


def _error(fn):
    """Call ``fn``, returning its ``(code, message)``; raises if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected a ClientError, the call succeeded")


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-loamr-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
