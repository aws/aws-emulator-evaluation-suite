"""list-shards-returns-disjoint-hash-ranges."""
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

def _get_shards(c, name):
    return c.list_shards(StreamName=name)["Shards"]

CHECK = "list-shards-returns-disjoint-hash-ranges"
GROUP = 'listing'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListShards on a multi-shard stream returns shards whose hash-key ranges partition the full
    128-bit space: contiguous (each shard's end+1 == next shard's start), starting at 0 and ending at
    2**128 - 1, with no gaps or overlaps.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=3)
    shards = sorted(_get_shards(c, name), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]))
    assert len(shards) == 3, f"expected 3 shards, got {len(shards)}"

    for i in range(len(shards) - 1):
        end = int(shards[i]["HashKeyRange"]["EndingHashKey"])
        nxt_start = int(shards[i + 1]["HashKeyRange"]["StartingHashKey"])
        assert nxt_start == end + 1, (
            f"gap/overlap between shard {i} ({shards[i]['ShardId']}, ending {end}) and shard "
            f"{i + 1} ({shards[i + 1]['ShardId']}, starting {nxt_start}); adjacent shards must "
            f"differ by exactly 1"
        )

    first_start = int(shards[0]["HashKeyRange"]["StartingHashKey"])
    assert first_start == 0, (
        f"the lowest shard {shards[0]['ShardId']!r} starts at {first_start}, expected 0: the "
        f"partition must cover the full 128-bit hash-key space from its floor"
    )
    last_end = int(shards[-1]["HashKeyRange"]["EndingHashKey"])
    assert last_end == (2 ** 128) - 1, (
        f"the highest shard {shards[-1]['ShardId']!r} ends at {last_end}, expected "
        f"{(2 ** 128) - 1}: the partition must cover the full 128-bit hash-key space to its ceiling"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
