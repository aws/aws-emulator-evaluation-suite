"""merge-shards-shard-with-itself-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-shards-shard-with-itself-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _poll(probe, pred, timeout_s=90.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_stream_retrying_limit(c, name, **params):
    deadline = time.monotonic() + 120.0
    while True:
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def _wait_shards_addressable(c, name):
    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    return _poll(_shards, lambda s: bool(s), description=f"shards of {name!r} addressable")


def _provisioned_stream(ctx, c, shard_count):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_retrying_limit(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        description=f"stream {name!r} ACTIVE",
    )
    _wait_shards_addressable(c, name)
    return name


def _open_shards(c, name):
    return [s for s in c.list_shards(StreamName=name)["Shards"] if "EndingSequenceNumber" not in s["SequenceNumberRange"]]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MergeShards naming the same ShardId as both ShardToMerge and AdjacentShardToMerge is
    rejected with InvalidArgumentException, leaves that shard open and childless, and a merge
    of the shard with its real adjacent neighbor still succeeds afterward."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=3)
    shards = sorted(_open_shards(c, name), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]))
    assert len(shards) == 3, f"expected 3 open shards, got {len(shards)}: {shards!r}"
    s0, s1, _s2 = shards

    code, message = _error(
        lambda: c.merge_shards(StreamName=name, ShardToMerge=s0["ShardId"], AdjacentShardToMerge=s0["ShardId"])
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_message = (
        f"Shards {s0['ShardId']} and {s0['ShardId']} in stream {name} under account {ctx.account} "
        "are not an adjacent pair of shards eligible for merging"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_reject = _open_shards(c, name)
    s0_after = next(s for s in after_reject if s["ShardId"] == s0["ShardId"])
    assert s0_after == s0, (
        f"shard {s0['ShardId']} must be unchanged after the rejected self-merge, "
        f"was {s0!r}, now {s0_after!r}"
    )
    assert not any(
        s.get("ParentShardId") == s0["ShardId"] and s.get("AdjacentParentShardId") == s0["ShardId"]
        for s in c.list_shards(StreamName=name)["Shards"]
    ), "the rejected self-merge must not have produced a child shard"

    c.merge_shards(StreamName=name, ShardToMerge=s0["ShardId"], AdjacentShardToMerge=s1["ShardId"])

    def _merged_child():
        shards = c.list_shards(StreamName=name)["Shards"]
        return [
            s for s in shards
            if s.get("ParentShardId") == s0["ShardId"] and s.get("AdjacentParentShardId") == s1["ShardId"]
        ]

    child = _poll(_merged_child, lambda kids: len(kids) == 1, description="merged child of s0+s1")
    assert "EndingSequenceNumber" not in child[0]["SequenceNumberRange"], (
        "the real-neighbor merge's child must be open"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
