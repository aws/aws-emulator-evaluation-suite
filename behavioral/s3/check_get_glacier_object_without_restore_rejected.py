"""get-glacier-object-without-restore-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-glacier-object-without-restore-rejected"
GROUP = "server-side"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject on an unrestored GLACIER object, which HeadObject and ListObjectsV2 still show, is
    refused with InvalidObjectState and its exact message, while a STANDARD sibling returns its bytes."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-rstneg")
    key = "cold.bin"
    control_key = "warm.bin"
    control_body = b"warm-storage-payload"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    # Positive control: an ordinary object in the same bucket is readable end to end,
    # so the InvalidObjectState assertion below cannot be scoring a target that just
    # denies every GetObject.
    s3.put_object(Bucket=bucket, Key=control_key, Body=control_body)
    control = s3.get_object(Bucket=bucket, Key=control_key)
    assert control["Body"].read() == control_body, "positive control GetObject must return its own bytes"

    s3.put_object(Bucket=bucket, Key=key, Body=b"cold-storage-payload", StorageClass="GLACIER")

    # Control plane is unaffected: the object is fully visible.
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["StorageClass"] == "GLACIER"
    assert "Restore" not in head, f"unrestored object must carry no Restore header, got {head.get('Restore')!r}"
    listing = s3.list_objects_v2(Bucket=bucket)
    assert any(o["Key"] == key for o in listing.get("Contents", []))

    # Data plane GET is rejected until a restore is requested and completes.
    err = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert err.get("Code") == "InvalidObjectState", f"expected InvalidObjectState, got {err}"
    assert err.get("Message") == "The operation is not valid for the object's storage class", err.get("Message")


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
