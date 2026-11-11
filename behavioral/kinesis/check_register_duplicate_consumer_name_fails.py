"""register-duplicate-consumer-name-fails."""
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

def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

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
    return name

def _wait_consumer_active(c, stream_arn, consumer_name, timeout_s=120, interval_s=2):
    _poll(
        lambda: c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)["ConsumerDescription"]["ConsumerStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"consumer {consumer_name} ACTIVE",
    )

def _wait_consumer_gone(c, stream_arn, consumer_name, timeout_s=150, interval_s=3):
    def probe():
        try:
            c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return "present"
    _poll(
        probe,
        lambda code: code == "ResourceNotFoundException",
        timeout_s, interval_s, f"consumer {consumer_name} gone after deregister",
    )

def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

CHECK = "register-duplicate-consumer-name-fails"
GROUP = 'consumers'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Registering a second consumer under a name already in use on the stream MUST fail while
    the first is live, must not disturb it, and the name becomes usable again once it is gone."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    arn = _stream_arn(c, name)
    consumer_name = ctx.unique_name("sim2real-behav-consumer-")

    def _cleanup_consumer():
        try:
            c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    # positive control: the first registration succeeds
    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    ctx.on_cleanup(_cleanup_consumer)
    _wait_consumer_active(c, arn, consumer_name)

    # break: a second registration under the same name on the same stream
    code, message = _error(
        lambda: c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected_message = (
        f"Consumer {consumer_name} under stream {name} already exists for account {ctx.account}."
    )
    assert message == expected_message, (
        f"duplicate RegisterStreamConsumer message {message!r}, expected {expected_message!r}"
    )

    # effect absent, via an independent read: the rejected duplicate left exactly
    # one consumer of this name, and it is still ACTIVE
    consumers = c.list_stream_consumers(StreamARN=arn)["Consumers"]
    matching = [x for x in consumers if x["ConsumerName"] == consumer_name]
    assert len(matching) == 1, (
        f"expected exactly one consumer named {consumer_name!r} after the rejected duplicate, "
        f"got {len(matching)}: {matching!r}"
    )
    assert matching[0]["ConsumerStatus"] == "ACTIVE", (
        f"expected surviving consumer {consumer_name!r} to remain ACTIVE, "
        f"got {matching[0]['ConsumerStatus']!r}"
    )

    # restore: remove the thing that was blocking the name
    c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    _wait_consumer_gone(c, arn, consumer_name)

    # the identical call now succeeds: the name is reusable once the blocker is gone
    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    _wait_consumer_active(c, arn, consumer_name)
    describe = c.describe_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    assert describe["ConsumerDescription"]["ConsumerStatus"] == "ACTIVE", (
        f"expected reused name {consumer_name!r} to reach ACTIVE after re-registration, "
        f"got {describe['ConsumerDescription']['ConsumerStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
