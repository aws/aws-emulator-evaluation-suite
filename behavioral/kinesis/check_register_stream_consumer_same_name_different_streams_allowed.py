"""register-stream-consumer-same-name-different-streams-allowed."""
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


def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]


def _wait_consumer_active(c, stream_arn, consumer_name, timeout_s=120, interval_s=2):
    _poll(
        lambda: c.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )["ConsumerDescription"]["ConsumerStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"consumer {consumer_name} ACTIVE",
    )


CHECK = "register-stream-consumer-same-name-different-streams-allowed"
GROUP = "consumers"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterStreamConsumer scopes ConsumerName uniqueness to the stream: the same name
    registers as two independent ACTIVE consumers with different ARNs on two streams."""
    c = ctx.client("kinesis")
    stream_a = _provisioned_stream(ctx, c, shard_count=1)
    stream_b = _provisioned_stream(ctx, c, shard_count=1)
    arn_a = _stream_arn(c, stream_a)
    arn_b = _stream_arn(c, stream_b)

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")

    reg_a = c.register_stream_consumer(StreamARN=arn_a, ConsumerName=consumer_name)
    consumer_arn_a = reg_a["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: c.deregister_stream_consumer(StreamARN=arn_a, ConsumerName=consumer_name))

    reg_b = c.register_stream_consumer(StreamARN=arn_b, ConsumerName=consumer_name)
    consumer_arn_b = reg_b["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: c.deregister_stream_consumer(StreamARN=arn_b, ConsumerName=consumer_name))

    assert consumer_arn_a != consumer_arn_b, (
        f"expected distinct consumer ARNs for the same name {consumer_name!r} on two "
        f"different streams, got the same ARN {consumer_arn_a!r} twice"
    )

    _wait_consumer_active(c, arn_a, consumer_name)
    _wait_consumer_active(c, arn_b, consumer_name)

    desc_a = c.describe_stream_consumer(StreamARN=arn_a, ConsumerName=consumer_name)["ConsumerDescription"]
    desc_b = c.describe_stream_consumer(StreamARN=arn_b, ConsumerName=consumer_name)["ConsumerDescription"]

    assert desc_a["ConsumerStatus"] == "ACTIVE", (
        f"expected consumer {consumer_name!r} on stream {stream_a} ACTIVE, got {desc_a['ConsumerStatus']!r}"
    )
    assert desc_b["ConsumerStatus"] == "ACTIVE", (
        f"expected consumer {consumer_name!r} on stream {stream_b} ACTIVE, got {desc_b['ConsumerStatus']!r}"
    )
    assert desc_a["ConsumerARN"] == consumer_arn_a, (
        f"DescribeStreamConsumer on stream {stream_a} returned ARN {desc_a['ConsumerARN']!r}, "
        f"expected the RegisterStreamConsumer-minted {consumer_arn_a!r}"
    )
    assert desc_b["ConsumerARN"] == consumer_arn_b, (
        f"DescribeStreamConsumer on stream {stream_b} returned ARN {desc_b['ConsumerARN']!r}, "
        f"expected the RegisterStreamConsumer-minted {consumer_arn_b!r}"
    )

    consumers_a = c.list_stream_consumers(StreamARN=arn_a)["Consumers"]
    names_a = [cons["ConsumerName"] for cons in consumers_a]
    assert names_a == [consumer_name], (
        f"expected ListStreamConsumers on stream {stream_a} to report exactly [{consumer_name!r}], "
        f"got {names_a!r}"
    )
    consumers_b = c.list_stream_consumers(StreamARN=arn_b)["Consumers"]
    names_b = [cons["ConsumerName"] for cons in consumers_b]
    assert names_b == [consumer_name], (
        f"expected ListStreamConsumers on stream {stream_b} to report exactly [{consumer_name!r}], "
        f"got {names_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
