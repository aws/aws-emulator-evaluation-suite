"""get-object-attributes-invalid-attribute-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-attributes-invalid-attribute-name-rejected"
GROUP = "representation"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes with an unrecognized attribute name is rejected with InvalidArgument
    rather than ignoring it; the same call with only valid names succeeds and returns the ETag."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-s3attrs-")
    key = "obj.bin"
    _create_bucket(ctx, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload-bytes")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    err = _client_error(
        lambda: s3.get_object_attributes(
            Bucket=bucket, Key=key, ObjectAttributes=["ETag", "NotARealAttribute"]
        )
    )
    assert err.get("Code") == "InvalidArgument", f"expected InvalidArgument, got {err!r}"
    assert err.get("Message") == "Invalid attribute name specified.", err

    # Positive control: only valid attribute names on the same object.
    ok = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ETag"])
    assert "ETag" in ok and ok["ETag"], f"positive control did not return an ETag: {ok!r}"


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
