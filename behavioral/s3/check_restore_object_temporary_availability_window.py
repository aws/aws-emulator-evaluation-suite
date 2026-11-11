"""restore-object-temporary-availability-window."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-object-temporary-availability-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GLACIER object is unreadable until restored; a second in-flight restore is rejected.

    The restored copy returns the original bytes, a longer re-restore extends the expiry, and
    restoring an active-tier INTELLIGENT_TIERING object fails with InvalidObjectState.
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "archived.bin"
    body = b"content that was pushed straight to glacier\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="GLACIER")

    # 1. Unrestored archived object: GetObject is rejected as InvalidObjectState.
    unrestored = _error(s3.get_object, Bucket=bucket, Key=key)
    assert unrestored == ("InvalidObjectState", "The operation is not valid for the object's storage class"), (
        f"expected GetObject on an unrestored GLACIER object to be rejected with "
        f"InvalidObjectState, got {unrestored!r}"
    )

    # 2. Kick off an expedited restore for 1 day of temporary availability.
    s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Expedited"}},
    )

    # 3. A second restore request while the first is still in flight is rejected.
    second = _error(
        s3.restore_object,
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Expedited"}},
    )
    assert second == ("RestoreAlreadyInProgress", "Object restore is already in progress"), (
        f"expected RestoreAlreadyInProgress, got {second!r}"
    )

    # 4. Expedited retrieval typically finishes in 1-5 minutes, hence the 6-minute bound.
    restored = _poll_until(
        lambda: s3.head_object(Bucket=bucket, Key=key).get("Restore", ""),
        lambda restore_hdr: 'ongoing-request="false"' in restore_hdr,
        timeout_s=360,
        interval_s=15,
    )
    if restored is None:
        raise AssertionError("Glacier expedited restore did not complete within the bounded poll window")
    first_expiry = _restore_expiry(restored)

    # 5. Once restored, GetObject succeeds and returns the exact original bytes.
    got = s3.get_object(Bucket=bucket, Key=key)
    got_body = got["Body"].read()
    assert got_body == body, f"expected restored bytes {body!r}, got {got_body!r}"
    assert got["StorageClass"] == "GLACIER", (
        f"expected the restored object's storage class to remain GLACIER, got {got['StorageClass']!r}"
    )

    # 6. Re-issuing RestoreObject for the already-active temporary copy with a LONGER period
    # succeeds (S3 updates/extends the restoration window in place) -- it is not an error.
    s3.restore_object(
        Bucket=bucket, Key=key,
        RestoreRequest={"Days": 5, "GlacierJobParameters": {"Tier": "Expedited"}},
    )
    extended = _poll_until(
        lambda: s3.head_object(Bucket=bucket, Key=key).get("Restore", ""),
        lambda restore_hdr: 'ongoing-request="false"' in restore_hdr,
        timeout_s=60,
        interval_s=5,
    )
    assert extended is not None, "extended restore never settled back to ongoing-request=false"
    second_expiry = _restore_expiry(extended)
    assert second_expiry > first_expiry, "re-issuing RestoreObject with more Days did not push the expiry out"

    # 7. A new INTELLIGENT_TIERING object starts in the Frequent Access tier, so there is nothing to
    # restore: S3 answers InvalidObjectState (as for STANDARD), not ObjectAlreadyInActiveTierError.
    it_key = "never-archived-it.bin"
    s3.put_object(Bucket=bucket, Key=it_key, Body=b"intelligent-tiering object, still in frequent access", StorageClass="INTELLIGENT_TIERING")
    active_tier = _error(
        s3.restore_object, Bucket=bucket, Key=it_key, RestoreRequest={"Days": 1}
    )
    assert active_tier == ("InvalidObjectState", "Restore is not allowed for the object's current storage class"), (
        f"expected RestoreObject on an already-active-tier INTELLIGENT_TIERING object to be "
        f"rejected with InvalidObjectState, got {active_tier!r}"
    )
    # The rejected call must not leave any restore state behind.
    it_head = s3.head_object(Bucket=bucket, Key=it_key)
    assert "Restore" not in it_head, f"unexpected Restore header on an active-tier object: {it_head.get('Restore')!r}"


def _restore_expiry(restore_header: str):
    """Parse the expiry-date of an x-amz-restore header value into a datetime."""
    import email.utils

    marker = 'expiry-date="'
    start = restore_header.index(marker) + len(marker)
    end = restore_header.index('"', start)
    return email.utils.parsedate_to_datetime(restore_header[start:end])


def _create_bucket(ctx, **extra: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-restore-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    kwargs.update(extra)
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "restore-object-temporary-availability-window"}]})

    def _cleanup() -> None:
        try:
            for o in s3.list_objects_v2(Bucket=name).get("Contents", []):
                _best_effort(lambda k=o["Key"]: s3.delete_object(Bucket=name, Key=k))
            _best_effort(lambda: s3.delete_bucket(Bucket=name))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _error(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[str, str]:
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn(*args, **kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
