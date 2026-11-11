"""tag-resource-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = 'tagging'
SERVICES = ['kinesis']


def _shards_addressable(kinesis, name):
    """True once ListShards answers; False while it still reports ResourceInUseException."""
    try:
        kinesis.list_shards(StreamName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
            return False
        raise
    return True


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _wait_stream_settled(kinesis, name, timeout_s=90.0, interval_s=3.0):
    """Poll a dependent control-plane read until it stops reporting a transitional state."""
    return _poll_until(
        lambda: _shards_addressable(kinesis, name),
        lambda ready: ready,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stream {name} control-plane consistency settle",
    )


def _wait_stream_active(kinesis, name, timeout_s=180.0, interval_s=3.0):
    """Wait for StreamStatus==ACTIVE, then wait for the stream to be *usable*.

    DescribeStreamSummary reporting ACTIVE is necessary but NOT sufficient: the Kinesis
    control plane is eventually consistent across API surfaces, so a dependent
    control-plane read can still observe the prior CREATING state for a short window
    after the summary flips.
    """
    resp = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name),
        lambda r: r["StreamDescriptionSummary"]["StreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stream {name} StreamStatus=ACTIVE",
    )
    _wait_stream_settled(kinesis, name)
    return resp


def _create_active_stream(ctx, kinesis, shard_count=1, timeout_s=180.0):
    """Create a stream and wait until it is ACTIVE *and* usable. Returns the stream name."""
    name = ctx.unique_name("sim2real-behav-kn-stream-")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(kinesis, name, timeout_s=timeout_s)
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes them."""
    kinesis = ctx.client("kinesis")
    name = _create_active_stream(ctx, kinesis)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
        "StreamARN"
    ]

    kinesis.tag_resource(
        ResourceARN=stream_arn, Tags={"env": "fidelity-test", "owner": "probe"}
    )
    tags = {
        t["Key"]: t["Value"]
        for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    assert tags.get("env") == "fidelity-test", (
        f"expected tag env=fidelity-test after TagResource, got env={tags.get('env')!r} "
        f"in {tags!r}"
    )
    assert tags.get("owner") == "probe", (
        f"expected tag owner=probe after TagResource, got owner={tags.get('owner')!r} "
        f"in {tags!r}"
    )

    kinesis.untag_resource(ResourceARN=stream_arn, TagKeys=["owner"])
    tags_after = {
        t["Key"]: t["Value"]
        for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    assert "owner" not in tags_after, (
        f"expected tag key 'owner' removed after UntagResource, still present in {tags_after!r}"
    )
    assert tags_after.get("env") == "fidelity-test", (
        f"expected untouched tag env=fidelity-test to survive UntagResource, "
        f"got env={tags_after.get('env')!r} in {tags_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
