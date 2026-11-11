"""create-stream-transitions-to-active."""
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
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    c.add_tags_to_stream(StreamName=name, Tags={"sim2real-check": CHECK})
    _wait_stream_ready(c, name)
    return name

CHECK = "create-stream-transitions-to-active"
GROUP = 'stream-lifecycle'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created stream reaches ACTIVE and exposes consistent describe fields."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    resp = c.describe_stream_summary(StreamName=name)
    summary = resp["StreamDescriptionSummary"]
    assert summary["StreamStatus"] == "ACTIVE", f"expected ACTIVE, got {summary['StreamStatus']!r}"
    assert summary["StreamName"] == name, f"expected StreamName {name!r}, got {summary['StreamName']!r}"
    assert summary["OpenShardCount"] == 1, f"expected 1 open shard, got {summary['OpenShardCount']!r}"
    assert summary["EncryptionType"] == "NONE", f"expected EncryptionType NONE, got {summary['EncryptionType']!r}"
    assert summary["RetentionPeriodHours"] == 24, f"expected default 24h retention, got {summary['RetentionPeriodHours']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
