"""annotation-stays-scoped-to-its-version-across-get-list-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "annotation-stays-scoped-to-its-version-across-get-list-delete"
GROUP = "versioning"
SERVICES = ["s3"]

_NO_SUCH_ANNOTATION = ("NoSuchAnnotation", "The specified annotation does not exist.")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An annotation written with no VersionId binds to the version current at that moment: a
    later PutObject's version has none of it on Get or List, a VersionId-qualified Get and List
    still see it, and a VersionId-qualified Delete clears it from only that version."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-annot-scope-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    key = "fulfillment-record.json"
    name = "shipment-tracking-id"
    payload_v1 = b"warehouse-west-dock-12"
    payload_v2 = b"warehouse-east-dock-04"

    v1 = s3.put_object(Bucket=bucket, Key=key, Body=b'{"stage":"received"}')["VersionId"]
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=v1))

    put_v1 = s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, AnnotationPayload=payload_v1)
    assert put_v1["ObjectVersionId"] == v1, (
        f"a PutObjectAnnotation with no VersionId bound to {put_v1['ObjectVersionId']!r}, "
        f"expected the version current at the time, {v1!r}"
    )

    v2 = s3.put_object(Bucket=bucket, Key=key, Body=b'{"stage":"shipped"}')["VersionId"]
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=v2))
    assert v2 != v1, f"a second PutObject must mint a distinct version, got {v2!r} again"

    # The new version carries no annotation of its own yet: an unqualified Get and List must
    # not see the one written against v1.
    expect_error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name),
        *_NO_SUCH_ANNOTATION,
    )
    listed_latest_before = s3.list_object_annotations(Bucket=bucket, Key=key)
    assert listed_latest_before["AnnotationCount"] == 0, (
        f"the new version should list no annotations yet, got "
        f"{listed_latest_before['AnnotationCount']}"
    )

    # The control: reading v1 explicitly still finds it, on both Get and List.
    control_get_v1 = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, VersionId=v1)
    control_payload_v1 = control_get_v1["AnnotationPayload"].read()
    assert control_payload_v1 == payload_v1, (
        f"VersionId={v1!r} should still read {payload_v1!r}, got {control_payload_v1!r}"
    )
    listed_v1 = s3.list_object_annotations(Bucket=bucket, Key=key, VersionId=v1)
    names_v1 = [a["AnnotationName"] for a in listed_v1.get("Annotations", [])]
    assert names_v1 == [name], f"VersionId={v1!r} should list [{name!r}], got {names_v1}"

    # Write v2's own annotation of the same name, under the same name, explicitly scoped to v2.
    s3.put_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, AnnotationPayload=payload_v2, VersionId=v2)
    unqualified_get = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name)
    unqualified_payload = unqualified_get["AnnotationPayload"].read()
    assert unqualified_payload == payload_v2, (
        f"an unqualified Get should now follow the current version and read {payload_v2!r}, "
        f"got {unqualified_payload!r}"
    )

    # Delete v1's annotation only; v2's own annotation of the same name must survive untouched.
    s3.delete_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, VersionId=v1)

    expect_error(
        lambda: s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, VersionId=v1),
        *_NO_SUCH_ANNOTATION,
    )
    listed_v1_after_delete = s3.list_object_annotations(Bucket=bucket, Key=key, VersionId=v1)
    assert listed_v1_after_delete["AnnotationCount"] == 0, (
        f"VersionId={v1!r} should list no annotations after its delete, got "
        f"{listed_v1_after_delete['AnnotationCount']}"
    )

    # The positive control: v2's annotation is untouched by a delete scoped to v1.
    surviving_get = s3.get_object_annotation(Bucket=bucket, Key=key, AnnotationName=name, VersionId=v2)
    surviving_payload = surviving_get["AnnotationPayload"].read()
    assert surviving_payload == payload_v2, (
        f"deleting v1's annotation must not touch v2's; expected {payload_v2!r}, got "
        f"{surviving_payload!r}"
    )
    listed_v2_after_delete = s3.list_object_annotations(Bucket=bucket, Key=key, VersionId=v2)
    names_v2_after_delete = [a["AnnotationName"] for a in listed_v2_after_delete.get("Annotations", [])]
    assert names_v2_after_delete == [name], (
        f"VersionId={v2!r} should still list [{name!r}] after v1's delete, got "
        f"{names_v2_after_delete}"
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
