"""describe-stream-pagination-exclusive-start-shard-id-and-has-more-shards."""
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
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
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


def _wait_shards_addressable(c, name, expected, timeout_s=120, interval_s=2):
    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    shards = _poll(_shards, lambda s: s is not None and len(s) == expected, timeout_s, interval_s,
                    f"stream {name} exposing {expected} addressable shards")
    return sorted(s["ShardId"] for s in shards)


CHECK = "describe-stream-pagination-exclusive-start-shard-id-and-has-more-shards"
GROUP = 'listing'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStream's Limit/ExclusiveStartShardId cursor pages a 3-shard stream once per shard.

    HasMoreShards is true exactly while shards remain, and paging past the last shard is empty."""
    c = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=3)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(c, name)
    all_shard_ids = _wait_shards_addressable(c, name, 3)
    assert len(all_shard_ids) == 3, f"expected a 3-shard stream, ListShards gave {all_shard_ids!r}"

    unpaged = c.describe_stream(StreamName=name)["StreamDescription"]
    assert sorted(s["ShardId"] for s in unpaged["Shards"]) == all_shard_ids, (
        f"unpaged DescribeStream returned shards {sorted(s['ShardId'] for s in unpaged['Shards'])!r}, "
        f"expected all three {all_shard_ids!r}"
    )
    assert unpaged["HasMoreShards"] is False, (
        f"an unpaged DescribeStream over a 3-shard stream with no Limit must have HasMoreShards "
        f"False, got {unpaged['HasMoreShards']!r}"
    )

    page1 = c.describe_stream(StreamName=name, Limit=1)["StreamDescription"]
    page1_ids = [s["ShardId"] for s in page1["Shards"]]
    assert page1_ids == [all_shard_ids[0]], (
        f"DescribeStream(Limit=1) over shards {all_shard_ids!r} must return exactly the first "
        f"shard, got {page1_ids!r}"
    )
    assert page1["HasMoreShards"] is True, (
        f"HasMoreShards must be True after returning 1 of 3 known shards, got {page1['HasMoreShards']!r}"
    )

    page2 = c.describe_stream(StreamName=name, Limit=1, ExclusiveStartShardId=page1_ids[0])["StreamDescription"]
    page2_ids = [s["ShardId"] for s in page2["Shards"]]
    assert page2_ids == [all_shard_ids[1]], (
        f"ExclusiveStartShardId={page1_ids[0]!r} must return the next shard "
        f"{all_shard_ids[1]!r} and exclude {page1_ids[0]!r} itself, got {page2_ids!r}"
    )
    assert page2["HasMoreShards"] is True, (
        f"HasMoreShards must be True after returning 2 of 3 known shards, got {page2['HasMoreShards']!r}"
    )

    page3 = c.describe_stream(StreamName=name, Limit=1, ExclusiveStartShardId=page2_ids[0])["StreamDescription"]
    page3_ids = [s["ShardId"] for s in page3["Shards"]]
    assert page3_ids == [all_shard_ids[2]], (
        f"ExclusiveStartShardId={page2_ids[0]!r} must return the last shard "
        f"{all_shard_ids[2]!r}, got {page3_ids!r}"
    )
    assert page3["HasMoreShards"] is False, (
        f"HasMoreShards must be False once all 3 of 3 known shards have been returned, "
        f"got {page3['HasMoreShards']!r}"
    )

    seen = page1_ids + page2_ids + page3_ids
    assert seen == all_shard_ids, (
        f"the three Limit=1 pages visited {seen!r}; expected the full shard list "
        f"{all_shard_ids!r} exactly once each, in order"
    )

    # ExclusiveStartShardId on the LAST shard must yield an empty, terminal page.
    page4 = c.describe_stream(StreamName=name, Limit=1, ExclusiveStartShardId=page3_ids[0])["StreamDescription"]
    assert page4["Shards"] == [], (
        f"ExclusiveStartShardId={page3_ids[0]!r} (the last shard) must return no further "
        f"shards, got {[s['ShardId'] for s in page4['Shards']]!r}"
    )
    assert page4["HasMoreShards"] is False, (
        f"HasMoreShards must be False once positioned past the last shard, got {page4['HasMoreShards']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
