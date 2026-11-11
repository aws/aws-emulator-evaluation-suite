"""delete-stream-with-active-consumer-requires-enforce-flag."""
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

def _expect_rejected(fn, description):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded and returned {result!r}")

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
    ctx.on_cleanup(lambda: _not_found(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)))
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

def _not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False

def _wait_consumer_gone(c, stream_arn, consumer_name, timeout_s=90, interval_s=2):
    _poll(
        lambda: _not_found(lambda: c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)),
        bool,
        timeout_s, interval_s, f"consumer {consumer_name} deregistered",
    )

def _wait_stream_deleted(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: _not_found(lambda: c.describe_stream_summary(StreamName=name)),
        bool,
        timeout_s, interval_s, f"stream {name} deleted",
    )

CHECK = "delete-stream-with-active-consumer-requires-enforce-flag"
GROUP = 'consumers'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStream without EnforceConsumerDeletion MUST fail while a consumer is registered,
    must leave the stream untouched, and the identical call must succeed once the consumer
    is gone."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    arn = _stream_arn(c, name)
    consumer_name = ctx.unique_name("sim2real-behav-consumer-")

    c.register_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    ctx.on_cleanup(lambda: _not_found(lambda: c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)))
    _wait_consumer_active(c, arn, consumer_name)

    code, message = _expect_rejected(
        lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=False),
        "DeleteStream while a consumer is registered",
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected_message = (
        f"DeleteStream can\u2019t delete {ctx.account}:{name} because there are consumers associated "
        f"with this data stream. To delete {name} anyway, set the EnforceConsumerDeletion parameter "
        "to true to force the deletion of all the consumers that are associated with it."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    status = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
    assert status == "ACTIVE", f"expected stream {name} to remain ACTIVE after the rejected delete, got {status}"

    c.deregister_stream_consumer(StreamARN=arn, ConsumerName=consumer_name)
    _wait_consumer_gone(c, arn, consumer_name)

    c.delete_stream(StreamName=name, EnforceConsumerDeletion=False)
    _wait_stream_deleted(c, name)
    final_code, final_message = _expect_rejected(
        lambda: c.describe_stream_summary(StreamName=name), "DescribeStreamSummary on the deleted stream"
    )
    assert final_code == "ResourceNotFoundException", f"expected stream {name} gone after delete, got {final_code}"
    expected_final = f"Stream {name} under account {ctx.account} not found."
    assert final_message == expected_final, f"expected message {expected_final!r}, got {final_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
