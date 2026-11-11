"""restore-object-server-side-tier-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-object-server-side-tier-transition"
GROUP = "server-side"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject on a GLACIER object drives a server-managed transition from
    not-restored -> restore-in-progress -> temporarily-restored, observable purely
    through HeadObject/GetObject state with no further client action."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-rst")
    key = "archived.bin"
    body = b"restore-me-content-0123456789"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key=key, Body=body, StorageClass="GLACIER")

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["StorageClass"] == "GLACIER"
    assert "Restore" not in head, "object should have no restore state before RestoreObject"

    refusal = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert refusal == ("InvalidObjectState", "The operation is not valid for the object's storage class"), (
        f"GET on un-restored GLACIER object should be InvalidObjectState, got {refusal!r}"
    )

    try:
        s3.restore_object(
            Bucket=bucket,
            Key=key,
            RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Expedited"}},
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"RestoreObject rejected (capacity/quota?): {exc}")

    # Immediately after the request, S3 should report restoration as in-progress.
    def _restore_header():
        h = s3.head_object(Bucket=bucket, Key=key)
        return h.get("Restore")

    in_progress = _poll_until(
        lambda: _restore_header(),
        lambda v: v is not None and 'ongoing-request="true"' in v,
        timeout_s=30.0,
        interval_s=2.0,
    )
    if in_progress is None:
        raise AssertionError("restore never reported ongoing-request=true within 30s")

    completed = _poll_until(
        lambda: _restore_header(),
        lambda v: v is not None and 'ongoing-request="false"' in v,
        timeout_s=240.0,
        interval_s=15.0,
    )
    if completed is None:
        raise AssertionError(
            "GLACIER expedited restore did not complete within the 4-minute bounded "
            "poll window; real AWS retrieval time can occasionally exceed test budget. "
            "(Capped below the suite's 300s body budget in record_ground_truth.py's "
            "_TIMEOUT table -- a longer window here would just be SIGKILLed uncleanly.)"
        )
    assert "expiry-date" in completed, f"completed restore missing expiry-date: {completed}"

    # No further client action required: GetObject now succeeds directly.
    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["Body"].read() == body
    assert got["StorageClass"] == "GLACIER"  # storage class is unchanged; only accessibility changes


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's implicit default region; passing a LocationConstraint for it
    # is itself a 400 (InvalidLocationConstraint), so the literal only guards that one region.
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
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value if predicate(value) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
