"""tag-apis-on-deregistered-consumer-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-apis-on-deregistered-consumer-arn-rejected"
GROUP = "tagging"
SERVICES = ["kinesis"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _must_fail(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_stream_active(kinesis, name, timeout_s=180.0):
    _poll(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, 3.0, f"stream {name} ACTIVE",
    )


def _wait_consumer_active(kinesis, consumer_arn, timeout_s=60.0):
    _poll(
        lambda: kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"]["ConsumerStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, 2.0, f"consumer {consumer_arn} ACTIVE",
    )


def _wait_consumer_gone(kinesis, consumer_arn, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} was not removed within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource, TagResource and UntagResource on a deregistered consumer's ARN
    fail with ResourceNotFoundException, while the same calls succeed before deregistration."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kds-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(
        _teardown(
            lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True),
            "ResourceNotFoundException",
        )
    )
    _wait_stream_active(kinesis, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamARN"]

    consumer_name = ctx.unique_name("sim2real-consumer-")
    registered = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    consumer_arn = registered["Consumer"]["ConsumerARN"]
    _wait_consumer_active(kinesis, consumer_arn)

    # Positive control: before deregistration the generic tagging APIs work against the consumer.
    kinesis.tag_resource(ResourceARN=consumer_arn, Tags={"env": "canary"})
    live_tags = _poll(
        lambda: {t["Key"]: t["Value"] for t in kinesis.list_tags_for_resource(ResourceARN=consumer_arn)["Tags"]},
        lambda m: m == {"env": "canary"},
        30, 2.0, "positive control: tag visible on the live consumer",
    )
    assert live_tags == {"env": "canary"}, f"positive control: expected {{'env': 'canary'}}, got {live_tags!r}"

    kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
    _wait_consumer_gone(kinesis, consumer_arn)

    code, message = _must_fail(lambda: kinesis.list_tags_for_resource(ResourceARN=consumer_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    expected_message = (
        f"Consumer {consumer_name} under stream: {stream_name}, account {ctx.account} not found."
    )
    assert message == expected_message, f"unexpected message {message!r}"

    code, message = _must_fail(
        lambda: kinesis.tag_resource(ResourceARN=consumer_arn, Tags={"env": "canary"})
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == expected_message, f"unexpected message {message!r}"

    code, message = _must_fail(
        lambda: kinesis.untag_resource(ResourceARN=consumer_arn, TagKeys=["env"])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == expected_message, f"unexpected message {message!r}"

    kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
