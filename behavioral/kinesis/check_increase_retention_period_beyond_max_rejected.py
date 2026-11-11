"""increase-retention-period-beyond-max-rejected."""
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


def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(c, name)
    return name


def _retention_hours(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["RetentionPeriodHours"]


CHECK = "increase-retention-period-beyond-max-rejected"
GROUP = "retention"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IncreaseStreamRetentionPeriod enforces the 8,760-hour (365-day) ceiling: 8,761 is rejected
    and retention stays unchanged, while 8,760 is accepted and visible in DescribeStreamSummary."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)

    before = _retention_hours(c, name)
    assert before == 24, f"expected a freshly created stream's RetentionPeriodHours to default to 24, got {before}"

    try:
        c.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=8761)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            "IncreaseStreamRetentionPeriod(RetentionPeriodHours=8761) unexpectedly succeeded"
        )

    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for RetentionPeriodHours=8761, got {code}"
    )
    expected_message = (
        "Maximum allowed retention period is 8760 hours. "
        "Requested retention period (8761 hours) is too long."
    )
    assert message == expected_message, (
        f"IncreaseStreamRetentionPeriod(8761) answered {message!r}, expected {expected_message!r}"
    )

    after_reject = _retention_hours(c, name)
    assert after_reject == 24, (
        f"rejected IncreaseStreamRetentionPeriod(8761) should leave retention at 24, got {after_reject}"
    )

    c.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=8760)
    after_ceiling = _poll(
        lambda: _retention_hours(c, name),
        lambda hours: hours == 8760,
        timeout_s=60, interval_s=2,
        description="RetentionPeriodHours=8760 visible in DescribeStreamSummary",
    )
    assert after_ceiling == 8760, (
        f"expected RetentionPeriodHours=8760 (the documented ceiling) to be accepted and "
        f"reflected in DescribeStreamSummary, got {after_ceiling}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
