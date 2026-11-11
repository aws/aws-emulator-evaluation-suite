"""disable-enhanced-monitoring-invalid-metric-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

CHECK = "disable-enhanced-monitoring-invalid-metric-fails"
GROUP = 'monitoring'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableEnhancedMonitoring with an unknown metric fails with ValidationException.
    A positive control proves the call shape works, and the enabled metrics are left untouched."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)

    def _enabled_metrics():
        describe = c.describe_stream_summary(StreamName=name)
        entries = describe["StreamDescriptionSummary"]["EnhancedMonitoring"]
        return {m for e in entries for m in e.get("ShardLevelMetrics", [])}

    # Baseline: enable every metric so the stream has real state for the negative to
    # (fail to) disturb -- an already-empty baseline can't distinguish "rejected" from
    # "accepted but there was nothing to change".
    c.enable_enhanced_monitoring(StreamName=name, ShardLevelMetrics=["ALL"])
    _poll(_enabled_metrics, lambda got: bool(got), 60, 2, f"stream {name} enhanced monitoring enabled")

    # Positive control: the same call shape, a real metric name, is accepted and shrinks
    # the enabled set.
    resp = c.disable_enhanced_monitoring(StreamName=name, ShardLevelMetrics=["IncomingBytes"])
    assert "IncomingBytes" not in resp["DesiredShardLevelMetrics"], (
        f"positive control did not drop IncomingBytes: {resp['DesiredShardLevelMetrics']!r}"
    )
    remaining = _poll(
        lambda: _enabled_metrics(),
        lambda got: "IncomingBytes" not in got,
        60, 2, f"stream {name} IncomingBytes disabled on stream summary",
    )
    assert remaining, f"positive control left no enabled metrics to protect: {remaining!r}"

    # Negative: an unknown metric name is rejected.
    error = _client_error(
        lambda: c.disable_enhanced_monitoring(StreamName=name, ShardLevelMetrics=["NotARealMetric"])
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r} ({error.get('Message')!r})"
    )
    expected_message = (
        "1 validation error detected: Value '[NotARealMetric]' at 'shardLevelMetrics' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
        "[ALL, IteratorAgeMilliseconds, IncomingBytes, WriteProvisionedThroughputExceeded, "
        "OutgoingRecords, ReadProvisionedThroughputExceeded, IncomingRecords, OutgoingBytes]]"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the rejected call must not have touched the metrics left enabled by
    # the positive control.
    after = _enabled_metrics()
    assert after == remaining, (
        f"the rejected DisableEnhancedMonitoring call changed enabled metrics from "
        f"{sorted(remaining)} to {sorted(after)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
