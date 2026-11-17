"""add-tags-to-stream-overwrites-existing-tag-value."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "add-tags-to-stream-overwrites-existing-tag-value"
GROUP = "tagging"
SERVICES = ["kinesis"]


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _until_tag_value(kinesis, stream_name, key, wanted_value, timeout_s=60.0, interval_s=2.0):
    """A tag write can lag ListTagsForStream; poll until the key's value equals ``wanted_value``."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        tag_map = {t["Key"]: t["Value"] for t in kinesis.list_tags_for_stream(StreamName=stream_name)["Tags"]}
        last = tag_map.get(key)
        if last == wanted_value:
            return tag_map
        time.sleep(interval_s)
    raise AssertionError(f"tag {key!r} never settled on {wanted_value!r}, last saw {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-tagging an existing key with AddTagsToStream replaces its value in place; the key does
    not appear twice and keys untouched by the second call keep their original value."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-ato-")

    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)

    kinesis.add_tags_to_stream(
        StreamName=name,
        Tags={"sim2real-ato-mutable": "first-value", "sim2real-ato-untouched": "stays"},
    )
    _until_tag_value(kinesis, name, "sim2real-ato-mutable", "first-value")

    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real-ato-mutable": "second-value"})
    tag_map = _until_tag_value(kinesis, name, "sim2real-ato-mutable", "second-value")

    all_tags = kinesis.list_tags_for_stream(StreamName=name)["Tags"]
    mutable_entries = [t for t in all_tags if t["Key"] == "sim2real-ato-mutable"]
    assert len(mutable_entries) == 1, (
        f"re-tagging an existing key must update it in place, not duplicate it: {mutable_entries!r}"
    )
    assert tag_map.get("sim2real-ato-untouched") == "stays", (
        f"a key the second AddTagsToStream call did not name must keep its value, got {tag_map!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
