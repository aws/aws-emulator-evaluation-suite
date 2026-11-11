"""object-annotation-name-too-long-rejected."""

from __future__ import annotations
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-annotation-name-too-long-rejected"
GROUP = 'object_annotations'
SERVICES = ['s3']


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


def _err_code(fn):
    """Call fn(); return the botocore Error (code, message) if a ClientError is raised.
    An unexpected success raises, so silently accepted input cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObjectAnnotation with an AnnotationName over the 512-byte maximum is rejected with
    AnnotationNameTooLong rather than truncated or accepted, leaving the annotations unchanged."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "annotation-guard.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"data")

    # Positive control: a compliant annotation name is accepted, so the account and
    # credentials are otherwise healthy for this operation.
    valid_name = "sim2real-guard"
    try:
        s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=valid_name, AnnotationPayload=b"ok")
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks PutObjectAnnotation support: {exc}") from exc

    too_long_name = "sim2real-" + ("x" * 2048)
    code, message = _err_code(
        lambda: s3.put_object_annotation(
            Bucket=bucket, Key=key, AnnotationName=too_long_name, AnnotationPayload=b"payload"
        )
    )
    assert code == "AnnotationNameTooLong", f"expected AnnotationNameTooLong, got {code!r}"
    assert message == "Your annotation name is too long.", f"expected the exact AnnotationNameTooLong message, got {message!r}"

    # The rejected call must not have created an annotation: only the valid control exists.
    listed = s3.list_object_annotations(Bucket=bucket, Key=key)
    names = [a["AnnotationName"] for a in listed.get("Annotations", [])]
    assert names == [valid_name], f"expected only {valid_name!r} to exist, got {names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
