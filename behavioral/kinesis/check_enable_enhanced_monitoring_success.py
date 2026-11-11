"""enable-enhanced-monitoring-success."""
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

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
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
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

CHECK = "enable-enhanced-monitoring-success"
GROUP = 'monitoring'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableEnhancedMonitoring records the requested shard-level metrics as desired.

    Real AWS expands the "ALL" shorthand into the concrete metric list in
    DesiredShardLevelMetrics rather than echoing "ALL" back.
    """
    c = ctx.client("kinesis")
    expanded = {
        "IncomingBytes",
        "IncomingRecords",
        "OutgoingBytes",
        "OutgoingRecords",
        "WriteProvisionedThroughputExceeded",
        "ReadProvisionedThroughputExceeded",
        "IteratorAgeMilliseconds",
    }
    name = _provisioned_stream(ctx, c, shard_count=1)
    resp = c.enable_enhanced_monitoring(StreamName=name, ShardLevelMetrics=["ALL"])
    desired = set(resp["DesiredShardLevelMetrics"])
    assert desired == expanded, (
        f"expected ALL to expand to exactly {sorted(expanded)}, got {sorted(desired)}"
    )

    def probe():
        describe = c.describe_stream_summary(StreamName=name)
        entries = describe["StreamDescriptionSummary"]["EnhancedMonitoring"]
        return {m for e in entries for m in e.get("ShardLevelMetrics", [])}

    metrics = _poll(
        probe,
        lambda got: bool(got),
        timeout_s=60,
        interval_s=2,
        description="enhanced monitoring metrics visible on stream summary",
    )
    assert metrics == expanded, (
        f"expected enabled metrics on summary to be exactly {sorted(expanded)}, got {sorted(metrics)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
