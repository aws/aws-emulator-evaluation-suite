"""describe-stream-consumer-nonexistent-fails."""
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
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            # Tags= so a tag-based cleanup can find this via the Resource Groups
            # Tagging API; an untagged stream is only findable by its name prefix.
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
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

def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

CHECK = "describe-stream-consumer-nonexistent-fails"
GROUP = 'error-semantics'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStreamConsumer for a consumer that was never registered MUST fail,
    while a real, registered consumer on the same stream describes cleanly — otherwise
    a target that rejects every DescribeStreamConsumer call would score identically."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    arn = _stream_arn(c, name)

    # Positive control: a consumer this check actually registered must describe
    # successfully, so the not-found case below is known to be specific to the
    # never-registered name rather than a blanket rejection.
    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    ctx.on_cleanup(lambda: c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name))
    _wait_consumer_active(c, arn, consumer_name)
    live = c.describe_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    assert live["ConsumerDescription"]["ConsumerStatus"] == "ACTIVE", (
        f"positive control: expected registered consumer ACTIVE, got {live['ConsumerDescription']['ConsumerStatus']}"
    )

    code, message = _error(
        lambda: c.describe_stream_consumer(StreamARN=arn, ConsumerName="never-registered")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Consumer never-registered under stream: {name}, account {ctx.account} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
