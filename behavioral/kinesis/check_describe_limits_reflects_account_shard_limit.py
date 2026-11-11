"""describe-limits-reflects-account-shard-limit."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-limits-reflects-account-shard-limit"
GROUP = "server-side"
SERVICES = ["kinesis"]

#: Fresh streams tried before a concurrent change elsewhere in the account counts as a failure.
_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLimits OpenShardCount grows by the new stream's shards after CreateStream, while
    the account's ShardLimit ceiling stays unchanged: usage moves, the limit does not."""
    kinesis = ctx.client("kinesis")

    shard_count = 2

    # OpenShardCount is account-wide, so a stream another run deletes meanwhile hides ours: each
    # attempt makes a fresh stream, and only a window in which the count rose by at least our own
    # shards is graded.
    for _ in range(_ATTEMPTS):
        baseline = kinesis.describe_limits()
        limit_before = baseline["ShardLimit"]
        before = baseline["OpenShardCount"]
        assert isinstance(limit_before, int) and limit_before > 0, (
            f"expected a positive ShardLimit, got {limit_before!r}"
        )

        name = ctx.unique_name("sim2real-behav-")
        kinesis.create_stream(
            StreamName=name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"}
        )
        ctx.on_cleanup(lambda name=name: kinesis.delete_stream(StreamName=name))
        _wait_stream_active(kinesis, name)

        after = kinesis.describe_limits()
        limit_after = after["ShardLimit"]
        open_after = after["OpenShardCount"]
        if open_after - before >= shard_count:
            break

    assert open_after - before >= shard_count, (
        f"expected OpenShardCount to grow by at least {shard_count} (from {before}), "
        f"got {open_after} (the last of {_ATTEMPTS} attempts, each with a fresh stream)"
    )
    # The ceiling and the usage are two different fields, tracked independently: creating
    # shards must not itself move the account's ShardLimit.
    assert limit_after == limit_before, (
        f"expected ShardLimit to stay {limit_before} after CreateStream, got {limit_after}"
    )


def _wait_stream_active(kinesis, name, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s (last={summary})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
