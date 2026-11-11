"""remove-tags-from-stream-removes-tag."""
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

CHECK = "remove-tags-from-stream-removes-tag"
GROUP = 'tagging'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTagsFromStream removes the tag so it no longer appears in ListTagsForStream."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    c.add_tags_to_stream(StreamName=name, Tags={"temp": "to-remove"})

    def probe():
        resp = c.list_tags_for_stream(StreamName=name)
        return {t["Key"]: t["Value"] for t in resp["Tags"]}

    # Tag reads lag writes in both directions; the pre-removal poll also proves the tag applied.
    before = _poll(
        probe,
        lambda m: m.get("temp") == "to-remove",
        timeout_s=30,
        interval_s=2,
        description="temp=to-remove tag visible on stream before removal",
    )
    assert before.get("temp") == "to-remove", f"expected temp=to-remove before removal, got {before!r}"

    c.remove_tags_from_stream(StreamName=name, TagKeys=["temp"])

    after = _poll(
        probe,
        lambda m: "temp" not in m,
        timeout_s=30,
        interval_s=2,
        description="temp tag absent from stream after removal",
    )
    assert "temp" not in after, f"expected temp tag removed after RemoveTagsFromStream, still present: {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
