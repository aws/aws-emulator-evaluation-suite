"""tag-resource-concurrent-updates-consistent."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-concurrent-updates-consistent"
GROUP = "concurrency"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sequential TagResource writes to one key keep the last value, and concurrent writes of
    different values leave exactly one entry holding one of the written values, never a merge."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-tag-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))

    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    stream_arn = summary["StreamARN"]

    # Sequential baseline: for a fixed key, the LAST submitted write wins.
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"race": "seq-1"})
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"race": "seq-2"})
    seq_entries = [t for t in _list_tags(kinesis, stream_arn) if t["Key"] == "race"]
    assert len(seq_entries) == 1, f"expected exactly one 'race' tag entry after sequential writes, got {seq_entries}"
    assert seq_entries[0]["Value"] == "seq-2", (
        f"expected sequential last-write-wins value 'seq-2', got {seq_entries[0]['Value']!r}"
    )

    # Concurrent racers: N threads set the SAME key to N DIFFERENT values, released by a
    # barrier so they fire as close to simultaneously as the client can arrange.
    values = [f"race-{i}" for i in range(6)]
    barrier = threading.Barrier(len(values))

    def _writer(value: str) -> None:
        barrier.wait()
        kinesis.tag_resource(ResourceARN=stream_arn, Tags={"race": value})

    with ThreadPoolExecutor(max_workers=len(values)) as pool:
        list(pool.map(_writer, values))

    race_entries = [t for t in _list_tags(kinesis, stream_arn) if t["Key"] == "race"]
    # No lost/merged state: exactly one entry survives for the contested key, and it is
    # one of the values a racer actually wrote (not corrupted, concatenated, or blank).
    assert len(race_entries) == 1, f"expected exactly one 'race' tag entry, got {race_entries}"
    assert race_entries[0]["Value"] in values, (
        f"expected race-winning value to be one of {values} (not corrupted/merged), "
        f"got {race_entries[0]['Value']!r}"
    )


def _list_tags(kinesis, resource_arn: str) -> list[dict[str, str]]:
    return kinesis.list_tags_for_resource(ResourceARN=resource_arn).get("Tags", [])


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _delete_stream(ctx, name: str) -> None:
    kinesis = ctx.client("kinesis")
    try:
        kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
