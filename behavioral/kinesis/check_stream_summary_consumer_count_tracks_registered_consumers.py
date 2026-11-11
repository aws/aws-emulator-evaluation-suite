"""stream-summary-consumer-count-tracks-registered-consumers."""
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


def _summary(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]


def _stream_arn(c, name):
    return _summary(c, name)["StreamARN"]


def _wait_consumer_active(c, stream_arn, consumer_name, timeout_s=120, interval_s=2):
    _poll(
        lambda: c.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )["ConsumerDescription"]["ConsumerStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"consumer {consumer_name} ACTIVE",
    )


def _describe_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "present"


def _deregister_tolerating_already_gone(c, stream_arn, consumer_name):
    try:
        c.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


CHECK = "stream-summary-consumer-count-tracks-registered-consumers"
GROUP = "consumers"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStreamSummary ConsumerCount tracks registered consumers exactly: 0, then +1 per
    consumer that reaches ACTIVE, then -1 once a deregistered consumer is gone, matching
    ListStreamConsumers."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    arn = _stream_arn(c, name)

    zero = _summary(c, name)
    assert zero["ConsumerCount"] == 0, (
        f"expected a freshly created stream to report ConsumerCount=0, got {zero['ConsumerCount']}"
    )

    consumer_a = ctx.unique_name("sim2real-behav-consumer-a-")
    consumer_b = ctx.unique_name("sim2real-behav-consumer-b-")

    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_a)
    ctx.on_cleanup(lambda: _deregister_tolerating_already_gone(c, arn, consumer_a))
    _wait_consumer_active(c, arn, consumer_a)

    one = _poll(
        lambda: _summary(c, name),
        lambda s: s["ConsumerCount"] == 1,
        timeout_s=60, interval_s=2,
        description="ConsumerCount reaches 1 after one consumer is ACTIVE",
    )
    assert one["ConsumerCount"] == 1, (
        f"expected ConsumerCount=1 with exactly one ACTIVE consumer, got {one['ConsumerCount']}"
    )

    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_b)
    ctx.on_cleanup(lambda: c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_b))
    _wait_consumer_active(c, arn, consumer_b)

    two = _poll(
        lambda: _summary(c, name),
        lambda s: s["ConsumerCount"] == 2,
        timeout_s=60, interval_s=2,
        description="ConsumerCount reaches 2 after both consumers are ACTIVE",
    )
    assert two["ConsumerCount"] == 2, (
        f"expected ConsumerCount=2 with two ACTIVE consumers, got {two['ConsumerCount']}"
    )

    c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_a)
    _poll(
        lambda: _describe_code(
            lambda: c.describe_stream_consumer(StreamARN=arn, ConsumerName=consumer_a)
        ),
        lambda code: code == "ResourceNotFoundException",
        timeout_s=150, interval_s=3,
        description="consumer_a gone after deregister",
    )

    back_to_one = _poll(
        lambda: _summary(c, name),
        lambda s: s["ConsumerCount"] == 1,
        timeout_s=60, interval_s=2,
        description="ConsumerCount returns to 1 after one consumer is deregistered",
    )
    assert back_to_one["ConsumerCount"] == 1, (
        f"expected ConsumerCount=1 after deregistering one of two consumers, got "
        f"{back_to_one['ConsumerCount']}"
    )

    remaining = [cons["ConsumerName"] for cons in c.list_stream_consumers(StreamARN=arn)["Consumers"]]
    assert remaining == [consumer_b], (
        f"expected ListStreamConsumers to report exactly [{consumer_b!r}] once "
        f"ConsumerCount dropped back to 1, got {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
