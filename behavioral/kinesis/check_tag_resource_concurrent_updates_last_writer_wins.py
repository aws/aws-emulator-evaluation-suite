"""tag-resource-concurrent-updates-last-writer-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "tag-resource-concurrent-updates-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent TagResource calls setting different values for one key both succeed and
    leave exactly one entry holding one of the two values, never a merge or both surviving."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(ctx, name)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
        "StreamARN"
    ]

    key = "sim2real-race-key"
    value_a = "racer-A-value"
    value_b = "racer-B-value"

    def write(value: str):
        kinesis.tag_resource(ResourceARN=stream_arn, Tags={key: value})
        return value

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write, value_a), pool.submit(write, value_b)]
        results = [f.result(timeout=30) for f in futures]

    # Both racers must have completed without raising (TagResource is a plain
    # overwrite, not a conditional write).
    assert set(results) == {value_a, value_b}, (
        f"expected both racers to return their own value {value_a!r}/{value_b!r}, got {results!r}"
    )

    all_tags = kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    # Read the raw entries for the contested key, not a dict comprehension: a
    # dict silently collapses duplicate keys, which would hide the exact failure
    # mode ("both survive as two entries under the same key") this check exists
    # to catch.
    race_entries = [t for t in all_tags if t["Key"] == key]
    assert len(race_entries) == 1, (
        f"expected exactly one tag entry for {key!r}, got {race_entries!r}"
    )
    final_value = race_entries[0]["Value"]
    # Exactly one clean value survives -- never a merge/concatenation of both,
    # never absent, never both keys.
    assert final_value in (value_a, value_b), (
        f"final tag value {final_value!r} was neither racer value {value_a!r} nor {value_b!r}"
    )


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
