"""copy-object-annotation-exclude-directive-skips-default-copies."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-annotation-exclude-directive-skips-default-copies"
GROUP = "object_annotations"
SERVICES = ["s3"]


def _delete_bucket(client, bucket):
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for o in page.get("Contents", []):
            client.delete_object(Bucket=bucket, Key=o["Key"])
    client.delete_bucket(Bucket=bucket)


def _rejection(fn) -> tuple[str, str]:
    """(code, message) of the AWS error fn() raises; raises itself when the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call succeeded where real AWS rejects it; it returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject copies the source's annotation byte for byte by default, while
    AnnotationDirective=EXCLUDE leaves the copy with none (NoSuchAnnotation); the source keeps it.
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-anncp-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    src_key = "src.txt"
    s3.put_object(Bucket=bucket, Key=src_key, Body=b"hello")
    s3.put_object_annotation(
        Bucket=bucket, Key=src_key, AnnotationName="latest-note",
        AnnotationPayload=b"copied annotation",
    )

    # Positive control: the default directive (no header at all) propagates the annotation.
    copied_key = "docs/annotated-copied.txt"
    s3.copy_object(
        Bucket=bucket, Key=copied_key, CopySource={"Bucket": bucket, "Key": src_key}
    )
    copied = s3.get_object_annotation(
        Bucket=bucket, Key=copied_key, AnnotationName="latest-note"
    )
    assert copied["AnnotationPayload"].read() == b"copied annotation", (
        "default CopyObject must propagate the source's annotation to the copy"
    )

    # Break exactly one thing: ask the copy to EXCLUDE annotations.
    excluded_key = "docs/annotated-excluded.txt"
    s3.copy_object(
        Bucket=bucket, Key=excluded_key, CopySource={"Bucket": bucket, "Key": src_key},
        AnnotationDirective="EXCLUDE",
    )
    code, message = _rejection(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=excluded_key, AnnotationName="latest-note")
    )
    assert code == "NoSuchAnnotation", (
        f"expected EXCLUDE to leave the copy with no 'latest-note' annotation, got {code!r}"
    )
    assert message == "The specified annotation does not exist.", (
        f"NoSuchAnnotation must carry S3's own message; got {message!r}"
    )

    # The source itself is untouched by either copy.
    source_still = s3.get_object_annotation(Bucket=bucket, Key=src_key, AnnotationName="latest-note")
    assert source_still["AnnotationPayload"].read() == b"copied annotation", (
        "the source object's own annotation must be unaffected by copying it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
