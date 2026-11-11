"""retention-period-limits-record-visibility-window."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retention-period-limits-record-visibility-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Records written under the default 24h retention stay readable via TRIM_HORIZON after
    IncreaseStreamRetentionPeriod; a decreasing target is rejected with InvalidArgumentException
    and leaves the retention unchanged."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-retention-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    _wait_stream_active(ctx, stream_name)
    shard_id = _get_only_shard_id(ctx, stream_name)

    summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    original_retention = summary["RetentionPeriodHours"]
    assert original_retention == 24, f"expected default retention of 24h, got {original_retention}"

    marker = b"before-retention-increase"
    kinesis.put_record(StreamName=stream_name, Data=marker, PartitionKey="pk-baseline")

    baseline_records = _read_all_trim_horizon(ctx, stream_name, shard_id)
    assert any(r["Data"] == marker for r in baseline_records), "baseline record not visible before change"

    new_retention = original_retention + 24  # 48h, strictly greater
    kinesis.increase_stream_retention_period(StreamName=stream_name, RetentionPeriodHours=new_retention)

    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "RetentionPeriodHours"
        ],
        lambda v: v == new_retention,
        timeout_s=60.0,
        interval_s=2.0,
    )
    # RetentionPeriodHours flips before the stream settles back to ACTIVE; a control-plane call
    # in that window gets a transient ResourceInUseException instead of the validation error.
    _wait_stream_active(ctx, stream_name)

    after_records = _read_all_trim_horizon(ctx, stream_name, shard_id)
    assert any(r["Data"] == marker for r in after_records), (
        "record written before the retention increase must still be visible via TRIM_HORIZON "
        "after the increase took effect"
    )

    # AWS accepts an equal target as a silent no-op despite the API docs, so use a strictly
    # decreasing one. ResourceInUseException can persist for over 60s after the first increase
    # even while the stream reports ACTIVE, hence the long retry bound.
    code, message = _error_with_retry(
        lambda: kinesis.increase_stream_retention_period(
            StreamName=stream_name, RetentionPeriodHours=original_retention
        ),
        retry_codes=("ResourceInUseException",),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for a decreasing retention target passed to "
        f"IncreaseStreamRetentionPeriod, got {code!r}"
    )
    expected_message = (
        f"Requested retention period ({original_retention} hours) for stream {stream_name} can "
        f"not be shorter than existing retention period ({new_retention} hours). Use "
        f"DecreaseRetentionPeriod API."
    )
    assert message == expected_message, (
        f"decreasing IncreaseStreamRetentionPeriod message {message!r}, expected {expected_message!r}"
    )

    unchanged_retention = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "RetentionPeriodHours"
    ]
    assert unchanged_retention == new_retention, (
        f"rejected IncreaseStreamRetentionPeriod call must not change retention period: "
        f"expected it to remain {new_retention}, got {unchanged_retention}"
    )


def _error_with_retry(
    fn: Callable[[], Any],
    *,
    retry_codes: tuple[str, ...],
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> tuple[Optional[str], Optional[str]]:
    """The (code, message) of the first non-transient ClientError ``fn`` raises; a code in
    ``retry_codes`` (the stream still settling a config change) is retried until ``timeout_s``.
    An unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code not in retry_codes or time.monotonic() >= deadline:
                return code, err.get("Message")
            time.sleep(interval_s)
            continue
        raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _get_only_shard_id(ctx, stream_name: str) -> str:
    kinesis = ctx.client("kinesis")
    shards = kinesis.list_shards(StreamName=stream_name)["Shards"]
    assert len(shards) >= 1, "expected at least one shard"
    return shards[0]["ShardId"]


def _read_all_trim_horizon(ctx, stream_name: str, shard_id: str) -> list[dict]:
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    out: list[dict] = []
    for _ in range(5):
        resp = kinesis.get_records(ShardIterator=iterator, Limit=1000)
        out.extend(resp["Records"])
        iterator = resp["NextShardIterator"]
        if not resp["Records"]:
            break
        time.sleep(0.5)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
