"""tag-value-empty-string-vs-absent-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-value-empty-string-vs-absent-preserved"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag explicitly set with an empty-string value is distinguishable, via
    ListTagsForResource, from a tag key that was never set at all."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-tagval-")
    _wait_for_shard_capacity(kinesis)
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    _wait_for_stream_active(ctx, name)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"EmptyValueTag": ""})

    by_key = _wait_for_tag(kinesis, stream_arn, "EmptyValueTag")

    assert "EmptyValueTag" in by_key, "an explicitly set, empty-value tag key must be present"
    assert by_key["EmptyValueTag"] == "", (
        f"expected an empty string value for EmptyValueTag, got {by_key['EmptyValueTag']!r}"
    )
    assert "NeverSetTag" not in by_key, "a tag key that was never set must be absent, not merely empty"


def _wait_for_shard_capacity(kinesis, needed=1, timeout_s=90.0):
    """Poll DescribeLimits until the account has at least `needed` free shards.
    DeleteStream's effect on OpenShardCount is eventually consistent, so a just-deleted
    stream may still count. Raises if no capacity frees up within timeout_s."""
    deadline = time.monotonic() + timeout_s
    limits = None
    while time.monotonic() < deadline:
        limits = kinesis.describe_limits()
        if limits["ShardLimit"] - limits["OpenShardCount"] >= needed:
            return limits
        time.sleep(3.0)
    raise AssertionError(
        f"shared account had no free shard capacity within {timeout_s}s "
        f"(ShardLimit={limits['ShardLimit'] if limits else '?'}, "
        f"OpenShardCount={limits['OpenShardCount'] if limits else '?'}); "
        "likely another large stream elsewhere in the account is still deleting"
    )


def _wait_for_tag(kinesis, stream_arn, key, timeout_s=30.0):
    """Tag visibility via ListTagsForResource can lag TagResource by a beat, so poll
    rather than assuming the write is immediately visible on the read path."""
    deadline = time.monotonic() + timeout_s
    by_key = {}
    while time.monotonic() < deadline:
        tags = kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
        by_key = {t["Key"]: t.get("Value") for t in tags}
        if key in by_key:
            return by_key
        time.sleep(2.0)
    raise AssertionError(f"tag {key!r} never became visible on {stream_arn} within {timeout_s}s")


def _wait_for_stream_active(ctx, name, timeout_s=180.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"stream {name} did not reach ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
