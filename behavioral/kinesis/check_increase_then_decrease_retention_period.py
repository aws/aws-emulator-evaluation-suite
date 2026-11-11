"""increase-then-decrease-retention-period."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "increase-then-decrease-retention-period"
GROUP = 'retention'
SERVICES = ['kinesis']


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _wait_stream_settled(kinesis, name, timeout_s=90.0, interval_s=3.0):
    """Poll a dependent control-plane read until it stops reporting a transitional state."""
    def _settled():
        try:
            kinesis.list_shards(StreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
                return False
            raise
        return True

    return _poll_until(
        _settled,
        lambda settled: settled,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stream {name} control-plane consistency settle",
    )


def _wait_stream_active(kinesis, name, timeout_s=180.0, interval_s=3.0):
    """Wait for StreamStatus==ACTIVE, then wait for the stream to be *usable*.

    DescribeStreamSummary reporting ACTIVE is necessary but NOT sufficient: the Kinesis
    control plane is eventually consistent across API surfaces, so ListShards /
    RegisterStreamConsumer / SplitShard can still observe the prior CREATING (or
    UPDATING) state for a short window after the summary flips. Gate on a real dependent
    read so callers get a stream they can use.
    """
    resp = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name),
        lambda r: r["StreamDescriptionSummary"]["StreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stream {name} StreamStatus=ACTIVE",
    )
    _wait_stream_settled(kinesis, name)
    return resp


def _create_active_stream(ctx, kinesis, shard_count=1, timeout_s=180.0):
    """Create a stream and wait until it is ACTIVE *and* usable. Returns the stream name."""
    name = ctx.unique_name("sim2real-behav-kn-stream-")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(kinesis, name, timeout_s=timeout_s)
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IncreaseStreamRetentionPeriod / DecreaseStreamRetentionPeriod both update RetentionPeriodHours."""
    kinesis = ctx.client("kinesis")
    name = _create_active_stream(ctx, kinesis)
    summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["RetentionPeriodHours"] == 24, summary["RetentionPeriodHours"]

    kinesis.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=48)
    _wait_stream_active(kinesis, name)
    summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["RetentionPeriodHours"] == 48, summary["RetentionPeriodHours"]

    kinesis.decrease_stream_retention_period(StreamName=name, RetentionPeriodHours=30)
    _wait_stream_active(kinesis, name)
    summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["RetentionPeriodHours"] == 30, summary["RetentionPeriodHours"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
