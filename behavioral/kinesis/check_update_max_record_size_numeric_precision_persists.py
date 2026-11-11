"""update-max-record-size-numeric-precision-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-max-record-size-numeric-precision-persists"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large MaxRecordSizeInKiB value set via UpdateMaxRecordSize is persisted and returned
    with exact numeric precision by DescribeStreamSummary, not rounded, truncated, or
    overflowed."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-maxrecsize-")
    _wait_for_shard_capacity(kinesis)
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    _wait_for_stream_active(ctx, name)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

    large_value = 10240  # KiB -- the maximum allowed value for MaxRecordSizeInKiB
    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=large_value)
    _wait_for_stream_active(ctx, name)  # StreamStatus cycles ACTIVE -> UPDATING -> ACTIVE

    summary = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary.get("MaxRecordSizeInKiB") == large_value:
            break
        time.sleep(3.0)
    assert summary is not None, f"stream {name} produced no DescribeStreamSummary response within 60s"
    assert summary.get("MaxRecordSizeInKiB") == large_value, (
        f"expected MaxRecordSizeInKiB={large_value} to persist exactly, "
        f"got {summary.get('MaxRecordSizeInKiB')!r}"
    )
    assert isinstance(summary["MaxRecordSizeInKiB"], int), "MaxRecordSizeInKiB must round-trip as an integer"


def _wait_for_shard_capacity(kinesis, needed=1, timeout_s=90.0):
    """Poll DescribeLimits until the account has at least `needed` free shards.
    DeleteStream's effect on OpenShardCount is eventually consistent, so a just-deleted
    stream may still count. Raises if no capacity frees up within timeout_s."""
    deadline = time.monotonic() + timeout_s
    limits = None
    while time.monotonic() < deadline:
        limits = kinesis.describe_limits()
        if limits["ShardLimit"] - limits["OpenShardCount"] >= needed:
            return limits
        time.sleep(3.0)
    raise AssertionError(
        f"shared account had no free shard capacity within {timeout_s}s "
        f"(ShardLimit={limits['ShardLimit'] if limits else '?'}, "
        f"OpenShardCount={limits['OpenShardCount'] if limits else '?'}); "
        "likely another large stream elsewhere in the account is still deleting"
    )


def _wait_for_stream_active(ctx, name, timeout_s=180.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"stream {name} did not reach ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
