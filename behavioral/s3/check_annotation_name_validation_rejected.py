"""annotation-name-validation-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "annotation-name-validation-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutObjectAnnotation rejects reserved-prefix and over-length names, leaving the annotation set unchanged."""
    s3 = ctx.client("s3")
    if not hasattr(s3, "put_object_annotation"):
        raise AssertionError("boto3 s3 client lacks put_object_annotation (S3 object annotations API not available)")

    bucket = _new_bucket(ctx, s3)
    key = "objects/target.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")

    # Positive control: a compliant annotation name succeeds.
    valid_name = "team.priority"
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=valid_name, AnnotationPayload=b"P1")
    got = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=valid_name)
    payload = got["AnnotationPayload"].read()
    assert payload == b"P1", f"expected positive-control payload b'P1', got {payload!r}"

    # Break precondition #1: annotation names beginning with the reserved "aws" prefix are disallowed.
    bad_name = "aws-reserved-name"
    code, message = _client_error(
        lambda: s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=bad_name, AnnotationPayload=b"x")
    )
    assert code == "InvalidAnnotation", f"expected InvalidAnnotation, got {code}"
    assert message == "Your annotation name cannot start with 'aws' or 's3'.", f"unexpected message {message!r}"

    # Break precondition #2: annotation names longer than the 512-byte maximum are disallowed.
    too_long_name = "n" * 513
    code2, message2 = _client_error(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=too_long_name, AnnotationPayload=b"x"
        )
    )
    assert code2 == "AnnotationNameTooLong", f"expected AnnotationNameTooLong, got {code2}"
    assert message2 == "Your annotation name is too long.", f"unexpected message {message2!r}"

    # Neither rejected call had any effect: only the valid annotation exists.
    listed = s3.list_object_annotations(Bucket=bucket, Key=key)
    names = [a["AnnotationName"] for a in listed.get("Annotations", [])]
    assert names == [valid_name], f"expected only {valid_name!r} to exist, got {names}"
    assert listed["AnnotationCount"] == 1, f"expected AnnotationCount 1, got {listed['AnnotationCount']}"


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-s3-behav-").lower()
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
