"""register-stream-consumer-lifecycle."""
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

def _describe_code(fn):
    """The error code ``fn`` raises, or "present" when the read succeeds (a poll probe)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "present"

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
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _wait_consumer_active(c, stream_arn, consumer_name, timeout_s=120, interval_s=2):
    _poll(
        lambda: c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)["ConsumerDescription"]["ConsumerStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"consumer {consumer_name} ACTIVE",
    )

def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

CHECK = "register-stream-consumer-lifecycle"
GROUP = 'consumers'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterStreamConsumer transitions a consumer to ACTIVE; after deregistration the
    consumer is independently confirmed gone, a further mutation against the dead id is
    rejected, and the freed name can be re-registered."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    arn = _stream_arn(c, name)
    consumer_name = ctx.unique_name("sim2real-behav-consumer-")

    reg_resp = c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    consumer_arn = reg_resp["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name))

    _wait_consumer_active(c, arn, consumer_name)

    describe = c.describe_stream_consumer(ConsumerARN=consumer_arn)
    status = describe["ConsumerDescription"]["ConsumerStatus"]
    assert status == "ACTIVE", f"expected consumer {consumer_name} ACTIVE, got {status}"

    c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)

    # Deregistration is ASYNCHRONOUS: the consumer first transitions to DELETING
    # and only later disappears, so DescribeStreamConsumer still succeeds right
    # after the call. Assert the terminal state is eventual absence.
    def probe():
        return _describe_code(
            lambda: c.describe_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
        )

    _poll(
        probe,
        lambda code: code == "ResourceNotFoundException",
        timeout_s=150,
        interval_s=3,
        description="consumer gone after deregister",
    )

    try:
        c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    except ClientError as exc:
        dead_code = exc.response.get("Error", {}).get("Code")
        dead_message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"deregistering already-gone consumer {consumer_name} unexpectedly succeeded"
        )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deregistering dead consumer {consumer_name}, got {dead_code}"
    )
    expected_message = (
        f"Consumer {consumer_name} under stream: {name}, account {ctx.account} not found."
    )
    assert dead_message == expected_message, (
        f"deregistering dead consumer answered {dead_message!r}, expected {expected_message!r}"
    )

    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    _wait_consumer_active(c, arn, consumer_name)

    # Terminal assertion is an independent read (DescribeStreamConsumer), not the
    # RegisterStreamConsumer response itself: confirm the freed name is really
    # re-registered at the destination, not just accepted in the response body.
    describe2 = c.describe_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    reused = describe2["ConsumerDescription"]
    assert reused["ConsumerName"] == consumer_name, (
        f"re-registered consumer name mismatch: expected {consumer_name}, got {reused['ConsumerName']!r}"
    )
    assert reused["ConsumerStatus"] == "ACTIVE", (
        f"re-registered consumer {consumer_name} in unexpected status {reused['ConsumerStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
