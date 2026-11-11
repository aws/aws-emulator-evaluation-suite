"""describe-limits-reflects-account-shard-quota."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-limits-reflects-account-shard-quota"
GROUP = "server-side"
SERVICES = ["kinesis"]

#: Fresh streams tried before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLimits reports the account's shard limit and current open-shard
    count, and the open-shard count rises to at least the baseline plus the open
    shards CreateStream and SplitShard add (other streams in the account may add more)."""
    kinesis = ctx.client("kinesis")

    # OpenShardCount is account-wide, so a stream another run deletes meanwhile hides ours: each
    # attempt makes a fresh stream, and only a window in which the count rose by at least our own
    # open shards is graded.
    for _ in range(_ATTEMPTS):
        name = ctx.unique_name("sim2real-behav-")
        baseline = kinesis.describe_limits()
        shard_limit = baseline["ShardLimit"]
        baseline_open = baseline["OpenShardCount"]
        assert isinstance(shard_limit, int) and shard_limit > 0, (
            f"expected a positive integer ShardLimit, got {shard_limit!r}"
        )

        kinesis.create_stream(
            StreamName=name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
        )
        ctx.on_cleanup(
            lambda name=name: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
        )
        _wait_stream_active(ctx, name)

        after_create = _poll_open_shard_count(kinesis, baseline_open + 1, timeout_s=60.0)

        shards = _list_shards_ready(kinesis, name, timeout_s=30.0)
        assert len(shards) == 1, (
            f"expected exactly 1 shard on a fresh ShardCount=1 stream, got {len(shards)}"
        )
        shard = shards[0]
        start = int(shard["HashKeyRange"]["StartingHashKey"])
        end = int(shard["HashKeyRange"]["EndingHashKey"])
        midpoint = str(start + (end - start) // 2)

        kinesis.split_shard(
            StreamName=name, ShardToSplit=shard["ShardId"], NewStartingHashKey=midpoint
        )
        _wait_stream_active(ctx, name)

        open_shards_after_split = _poll_open_shard_count(
            kinesis, baseline_open + 2, timeout_s=60.0
        )
        if after_create >= baseline_open + 1 and open_shards_after_split >= baseline_open + 2:
            break

    # OpenShardCount is account-wide and other runs share the account, so it is a lower bound.
    assert after_create >= baseline_open + 1, (
        f"expected OpenShardCount >= {baseline_open + 1} after CreateStream(ShardCount=1), "
        f"got {after_create} (the last of {_ATTEMPTS} attempts, each with a fresh stream)"
    )
    # Splitting one open shard into two closes the original and opens two new
    # ones: net +1 open shard relative to the single-shard stream, so +2 vs
    # baseline.
    assert open_shards_after_split >= baseline_open + 2, (
        f"expected OpenShardCount >= {baseline_open + 2} after SplitShard "
        f"(net +1 open shard over the single-shard stream), got {open_shards_after_split} "
        f"(the last of {_ATTEMPTS} attempts, each with a fresh stream)"
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


def _poll_open_shard_count(kinesis, expected: int, timeout_s: float) -> int:
    """OpenShardCount once it reaches ``expected``, else the last value read at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = kinesis.describe_limits()["OpenShardCount"]
        if last >= expected or time.monotonic() >= deadline:
            return last
        time.sleep(3)


def _list_shards_ready(kinesis, name: str, timeout_s: float) -> list:
    """ListShards' own view of a stream can lag DescribeStreamSummary's StreamStatus by a
    few seconds: real AWS returns ACTIVE from the latter while the former still raises
    ResourceInUseException(state=CREATING) for the same stream. Retry through that window
    rather than treating ACTIVE as sufficient."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return kinesis.list_shards(StreamName=name)["Shards"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException":
                raise
            last_error = err
            time.sleep(2)
    raise AssertionError(
        f"ListShards({name}) never left ResourceInUseException within {timeout_s}s "
        f"after DescribeStreamSummary reported ACTIVE, last error: {last_error}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
