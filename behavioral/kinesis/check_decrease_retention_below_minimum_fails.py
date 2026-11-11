"""decrease-retention-below-minimum-fails."""
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

def _refusal(fn):
    """Error code and message of a call that MUST be refused. A success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

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

def _retention_hours(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["RetentionPeriodHours"]

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

CHECK = "decrease-retention-below-minimum-fails"
GROUP = 'retention'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DecreaseStreamRetentionPeriod to 1h fails with the exact InvalidArgumentException naming the
    24-hour minimum and leaves retention unchanged, while a decrease from 48h to 24h succeeds."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    assert _retention_hours(c, name) == 24, "fresh stream should start at the 24h default"

    c.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=48)
    _wait_stream_active(c, name)
    assert _retention_hours(c, name) == 48, "setup: increase to 48h did not apply"

    c.decrease_stream_retention_period(StreamName=name, RetentionPeriodHours=24)
    _wait_stream_active(c, name)
    assert _retention_hours(c, name) == 24, "positive control: decrease to the 24h floor did not apply"

    code, message = _refusal(
        lambda: c.decrease_stream_retention_period(StreamName=name, RetentionPeriodHours=1)
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected = (
        "Minimum allowed retention period is 24 hours. "
        "Requested retention period (1 hours) is too short."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert _retention_hours(c, name) == 24, "rejected decrease below the minimum must leave retention unchanged"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
