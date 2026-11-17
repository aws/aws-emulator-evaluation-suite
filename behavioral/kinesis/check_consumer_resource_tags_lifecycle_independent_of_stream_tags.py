"""consumer-resource-tags-lifecycle-independent-of-stream-tags."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "consumer-resource-tags-lifecycle-independent-of-stream-tags"
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


def _tags_for(kinesis, arn):
    return {t["Key"]: t["Value"] for t in kinesis.list_tags_for_resource(ResourceARN=arn)["Tags"]}


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A consumer's generic-API tags (set at registration, edited after) live in a tag
    store separate from its parent stream's, which keeps its own tags unchanged throughout."""
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

    stream_tags = {"owner": "data-platform", "env": "staging"}
    kinesis.tag_resource(ResourceARN=stream_arn, Tags=stream_tags)
    _poll(
        lambda: _tags_for(kinesis, stream_arn),
        lambda m: m == stream_tags,
        30, 2.0, "stream's own tags visible via ListTagsForResource",
    )

    consumer_name = ctx.unique_name("sim2real-consumer-")
    consumer_tags = {"team": "ingest", "env": "canary", "project": "fanout"}
    registered = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name, Tags=consumer_tags
    )
    consumer_arn = registered["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(
        _teardown(
            lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn),
            "ResourceNotFoundException",
        )
    )
    _wait_consumer_active(kinesis, consumer_arn)

    seen = _poll(
        lambda: _tags_for(kinesis, consumer_arn),
        lambda m: m == consumer_tags,
        30, 2.0, "consumer's RegisterStreamConsumer tags visible via ListTagsForResource",
    )
    assert seen == consumer_tags, f"expected consumer tags {consumer_tags!r}, got {seen!r}"

    stream_seen = _tags_for(kinesis, stream_arn)
    assert stream_seen == stream_tags, (
        f"registering a consumer with its own tags changed the stream's tags: {stream_seen!r}"
    )

    kinesis.tag_resource(ResourceARN=consumer_arn, Tags={"stage": "rollout"})
    expected_after_tag = {**consumer_tags, "stage": "rollout"}
    after_tag = _poll(
        lambda: _tags_for(kinesis, consumer_arn),
        lambda m: m == expected_after_tag,
        30, 2.0, "TagResource addition visible on the consumer",
    )
    assert after_tag == expected_after_tag, f"expected {expected_after_tag!r} after TagResource, got {after_tag!r}"

    stream_after_tag = _tags_for(kinesis, stream_arn)
    assert stream_after_tag == stream_tags, (
        f"tagging the consumer changed the stream's own tags: {stream_after_tag!r}"
    )

    kinesis.untag_resource(ResourceARN=consumer_arn, TagKeys=["env"])
    expected_after_untag = {k: v for k, v in expected_after_tag.items() if k != "env"}
    after_untag = _poll(
        lambda: _tags_for(kinesis, consumer_arn),
        lambda m: m == expected_after_untag,
        30, 2.0, "UntagResource removal visible on the consumer",
    )
    assert after_untag == expected_after_untag, (
        f"expected {expected_after_untag!r} after UntagResource, got {after_untag!r}"
    )

    stream_after_untag = _tags_for(kinesis, stream_arn)
    assert stream_after_untag == stream_tags, (
        f"untagging the consumer changed the stream's own tags: {stream_after_untag!r}"
    )

    kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
    kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
