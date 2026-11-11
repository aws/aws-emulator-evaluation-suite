"""tag-resource-unicode-value-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode text set via TagResource is returned unchanged by
    ListTagsForResource, and UntagResource cleanly removes a unicode-keyed tag."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(ctx, kinesis, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "StreamARN"
    ]

    tag_key = "unicode-label"
    tag_value = "日本語-タグ-données-метка"
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={tag_key: tag_value})

    tag_map = _wait_for_tag(ctx, kinesis, stream_arn, tag_key)
    assert tag_map[tag_key] == tag_value, f"tag value corrupted: {tag_map[tag_key]!r} != {tag_value!r}"

    kinesis.untag_resource(ResourceARN=stream_arn, TagKeys=[tag_key])
    remaining_keys = {
        t["Key"] for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    assert tag_key not in remaining_keys, (
        f"UntagResource did not remove unicode-keyed tag {tag_key!r}; still present: {remaining_keys!r}"
    )


def _wait_stream_active(ctx, kinesis, stream_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_for_tag(ctx, kinesis, stream_arn, tag_key, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        raw = kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
        tag_map = {t["Key"]: t["Value"] for t in raw}
        if tag_key in tag_map:
            return tag_map
        time.sleep(2)
    raise AssertionError(f"tag {tag_key!r} never appeared on {stream_arn}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
