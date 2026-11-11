"""legacy-and-generic-tag-apis-share-the-same-tag-store."""
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


def _tags_by_stream_name(c, name):
    return {t["Key"]: t["Value"] for t in c.list_tags_for_stream(StreamName=name)["Tags"]}


def _tags_by_arn(c, arn):
    return {t["Key"]: t["Value"] for t in c.list_tags_for_resource(ResourceARN=arn)["Tags"]}


CHECK = "legacy-and-generic-tag-apis-share-the-same-tag-store"
GROUP = "tagging"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Stream-name tag APIs (AddTagsToStream etc.) and ARN tag APIs (TagResource etc.) share one
    tag set: tags written or removed through either surface are reflected by the other."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    arn = _stream_arn(c, name)

    c.add_tags_to_stream(StreamName=name, Tags={"legacy-key": "legacy-value"})
    via_resource = _poll(
        lambda: _tags_by_arn(c, arn),
        lambda m: m.get("legacy-key") == "legacy-value",
        timeout_s=30, interval_s=2,
        description="AddTagsToStream tag visible via ListTagsForResource",
    )
    assert via_resource.get("legacy-key") == "legacy-value", (
        f"expected legacy-key=legacy-value visible via ListTagsForResource after "
        f"AddTagsToStream, got tags={via_resource!r}"
    )

    c.tag_resource(ResourceARN=arn, Tags={"generic-key": "generic-value"})
    via_stream = _poll(
        lambda: _tags_by_stream_name(c, name),
        lambda m: m.get("generic-key") == "generic-value" and m.get("legacy-key") == "legacy-value",
        timeout_s=30, interval_s=2,
        description="both tags visible via ListTagsForStream after TagResource",
    )
    assert via_stream.get("generic-key") == "generic-value", (
        f"expected generic-key=generic-value visible via ListTagsForStream after "
        f"TagResource, got tags={via_stream!r}"
    )
    assert via_stream.get("legacy-key") == "legacy-value", (
        f"expected the earlier legacy-key=legacy-value to still be visible via "
        f"ListTagsForStream, got tags={via_stream!r}"
    )

    c.remove_tags_from_stream(StreamName=name, TagKeys=["legacy-key"])
    via_resource_after_remove = _poll(
        lambda: _tags_by_arn(c, arn),
        lambda m: "legacy-key" not in m,
        timeout_s=30, interval_s=2,
        description="legacy-key absent via ListTagsForResource after RemoveTagsFromStream",
    )
    assert "legacy-key" not in via_resource_after_remove, (
        f"expected legacy-key gone via ListTagsForResource after RemoveTagsFromStream, "
        f"got tags={via_resource_after_remove!r}"
    )
    assert via_resource_after_remove.get("generic-key") == "generic-value", (
        f"RemoveTagsFromStream(legacy-key) must not disturb generic-key, "
        f"got tags={via_resource_after_remove!r}"
    )

    c.untag_resource(ResourceARN=arn, TagKeys=["generic-key"])
    via_stream_after_untag = _poll(
        lambda: _tags_by_stream_name(c, name),
        lambda m: "generic-key" not in m,
        timeout_s=30, interval_s=2,
        description="generic-key absent via ListTagsForStream after UntagResource",
    )
    assert "legacy-key" not in via_stream_after_untag and "generic-key" not in via_stream_after_untag, (
        f"expected both legacy-key and generic-key gone via ListTagsForStream after "
        f"removing each through its own API, got {via_stream_after_untag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
