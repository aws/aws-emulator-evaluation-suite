"""restore-object-ttl-expiry-reverts."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-object-ttl-expiry-reverts"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject with a finite Days value answers 202 and HeadObject reports an ongoing Restore
    header; a second RestoreObject while it is open fails with RestoreAlreadyInProgress and its exact
    message and leaves the Restore header and storage class unchanged."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-ttl")
    key = "archived.bin"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=b"ttl-window-payload", StorageClass="GLACIER")

    # No restore window is open yet -> nothing to be "already in progress" against.
    first = s3.restore_object(Bucket=bucket, Key=key, RestoreRequest={"Days": 1})
    assert first["ResponseMetadata"]["HTTPStatusCode"] == 202, (
        f"first RestoreObject call should be accepted with 202, got "
        f"{first['ResponseMetadata']['HTTPStatusCode']}"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    restore_header = head.get("Restore")
    assert restore_header is not None, "HeadObject should show an open restore TTL window"
    assert 'ongoing-request="true"' in restore_header, f"unexpected Restore header: {restore_header}"

    # A second RestoreObject while the window is already open is rejected -- this
    # is the deterministic, fast-observable half of the TTL-window state machine.
    code, message = _error(
        lambda: s3.restore_object(Bucket=bucket, Key=key, RestoreRequest={"Days": 1})
    )
    assert code == "RestoreAlreadyInProgress", (
        f"expected RestoreAlreadyInProgress for a concurrent restore, got {code!r}"
    )
    assert message == "Object restore is already in progress", (
        f"expected the exact RestoreAlreadyInProgress message, got {message!r}"
    )

    # Effect absent: the rejected second call did not open a second window or alter
    # the one already in flight.
    head_after = s3.head_object(Bucket=bucket, Key=key)
    assert head_after.get("Restore") == restore_header, (
        f"the rejected concurrent restore changed the window: {restore_header!r} -> "
        f"{head_after.get('Restore')!r}"
    )
    assert head_after.get("StorageClass") == head.get("StorageClass"), (
        "the rejected concurrent restore changed the object's storage class"
    )


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
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects a concurrent RestoreObject, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
