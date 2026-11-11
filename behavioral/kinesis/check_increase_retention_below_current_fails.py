"""increase-retention-below-current-fails."""
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
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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
    _wait_stream_ready(c, name)
    c.add_tags_to_stream(StreamName=name, Tags={"env": "behavioral-check"})
    return name

CHECK = "increase-retention-below-current-fails"
GROUP = 'retention'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IncreaseStreamRetentionPeriod below the current retention fails with InvalidArgumentException
    and its exact message, leaving retention unchanged after a genuine increase to 48 hours."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)

    # A value equal to the current retention is accepted as a no-op, so raise it first.
    c.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=48)
    _wait_stream_ready(c, name)
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["RetentionPeriodHours"] == 48, (
        f"positive control failed: expected retention 48 after a genuine increase, "
        f"got {summary['RetentionPeriodHours']}"
    )

    # 36 is above the 24-hour minimum, so only the current 48-hour retention can refuse it.
    error = _client_error(
        lambda: c.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=36)
    )
    assert error.get("Code") == "InvalidArgumentException", (
        f"expected InvalidArgumentException, got {error.get('Code')}"
    )
    expected_message = (
        f"Requested retention period (36 hours) for stream {name} can not be shorter than "
        f"existing retention period (48 hours). Use DecreaseRetentionPeriod API."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["RetentionPeriodHours"] == 48, (
        f"rejected IncreaseStreamRetentionPeriod(36) must leave retention unchanged at 48, "
        f"got {summary['RetentionPeriodHours']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
