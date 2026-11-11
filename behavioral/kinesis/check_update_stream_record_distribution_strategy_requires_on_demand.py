"""update-stream-record-distribution-strategy-requires-on-demand."""
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


def _on_demand_stream(ctx, c):
    name = ctx.unique_name("sim2real-behav-kds-od-")
    _create_stream_with_retry(
        c, name, StreamModeDetails={"StreamMode": "ON_DEMAND"}, Tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(c, name)
    return name


def _summary(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]


def _stream_arn(c, name):
    return _summary(c, name)["StreamARN"]


CHECK = "update-stream-record-distribution-strategy-requires-on-demand"
GROUP = "capacity-mode"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Setting AUTO on a provisioned stream is refused with ValidationException and leaves no
    RecordDistributionStrategy, while on an on-demand stream AUTO and USER_PARTITION_KEY both
    round-trip through DescribeStreamSummary."""
    c = ctx.client("kinesis")
    provisioned_name = _provisioned_stream(ctx, c, shard_count=1)
    provisioned_arn = _stream_arn(c, provisioned_name)

    before = _summary(c, provisioned_name)
    assert before.get("RecordDistributionStrategy") is None, (
        f"expected a freshly created provisioned stream, which does not support the "
        f"record distribution strategy setting at all, to report no "
        f"RecordDistributionStrategy, got {before.get('RecordDistributionStrategy')!r}"
    )

    try:
        c.update_stream_record_distribution_strategy(
            StreamARN=provisioned_arn, RecordDistributionStrategy="AUTO"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"UpdateStreamRecordDistributionStrategy(AUTO) unexpectedly succeeded on the "
            f"provisioned stream {provisioned_name}"
        )

    assert code == "ValidationException", (
        f"expected ValidationException setting AUTO on a provisioned stream, got {code}"
    )
    expected_message = (
        f"Request is invalid. Stream {provisioned_name} under account "
        f"{ctx.account} is in Provisioned mode."
    )
    assert message == expected_message, (
        f"UpdateStreamRecordDistributionStrategy(AUTO) on provisioned stream "
        f"{provisioned_name} answered {message!r}, expected {expected_message!r}"
    )

    after_reject = _summary(c, provisioned_name)
    assert after_reject.get("RecordDistributionStrategy") is None, (
        f"rejected UpdateStreamRecordDistributionStrategy should leave the provisioned "
        f"stream reporting no RecordDistributionStrategy, got "
        f"{after_reject.get('RecordDistributionStrategy')!r}"
    )

    # Positive control: the identical call succeeds on an on-demand stream, and the
    # value round-trips in both directions through DescribeStreamSummary.
    on_demand_name = _on_demand_stream(ctx, c)
    on_demand_arn = _stream_arn(c, on_demand_name)

    before_od = _summary(c, on_demand_name)
    assert before_od.get("RecordDistributionStrategy") == "USER_PARTITION_KEY", (
        f"expected a freshly created on-demand stream's default "
        f"RecordDistributionStrategy to be USER_PARTITION_KEY, got "
        f"{before_od.get('RecordDistributionStrategy')!r}"
    )

    c.update_stream_record_distribution_strategy(
        StreamARN=on_demand_arn, RecordDistributionStrategy="AUTO"
    )
    after_auto = _poll(
        lambda: _summary(c, on_demand_name),
        lambda s: s.get("RecordDistributionStrategy") == "AUTO",
        timeout_s=60, interval_s=2,
        description="RecordDistributionStrategy=AUTO visible in DescribeStreamSummary",
    )
    assert after_auto.get("RecordDistributionStrategy") == "AUTO", (
        f"expected RecordDistributionStrategy=AUTO to be accepted and reflected on the "
        f"on-demand stream {on_demand_name}, got {after_auto.get('RecordDistributionStrategy')!r}"
    )

    c.update_stream_record_distribution_strategy(
        StreamARN=on_demand_arn, RecordDistributionStrategy="USER_PARTITION_KEY"
    )
    after_back = _poll(
        lambda: _summary(c, on_demand_name),
        lambda s: s.get("RecordDistributionStrategy") == "USER_PARTITION_KEY",
        timeout_s=60, interval_s=2,
        description="RecordDistributionStrategy=USER_PARTITION_KEY visible in DescribeStreamSummary",
    )
    assert after_back.get("RecordDistributionStrategy") == "USER_PARTITION_KEY", (
        f"expected switching back to USER_PARTITION_KEY to be accepted and reflected on "
        f"the on-demand stream {on_demand_name}, got "
        f"{after_back.get('RecordDistributionStrategy')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
