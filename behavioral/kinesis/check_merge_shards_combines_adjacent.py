"""merge-shards-combines-adjacent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# _register_stream_teardown and the Tags= on CreateStream exist because a cleanup that discovers
# streams through the Resource Groups Tagging API cannot see an untagged one, and a bare
# on_cleanup(delete_stream) is refused with ResourceInUseException while the stream is UPDATING,
# which is exactly the state a check that just resharded can leave it in.


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

def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    """Delete the stream at teardown and prove it is gone.

    DeleteStream is refused with ResourceInUseException while the stream is CREATING or
    UPDATING, so a bare ``on_cleanup(delete_stream)`` fails exactly when a check has just
    resharded — leaving a stream that bills shard-hours forever.
    """

    def _teardown():
        deadline = time.monotonic() + timeout_s
        last = None
        deleted = False
        while time.monotonic() < deadline:
            try:
                c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
                deleted = True
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ResourceInUseException", "LimitExceededException"):
                    raise
                last = code
                time.sleep(interval_s)
        if not deleted:
            raise AssertionError(
                f"stream {name} never reached a deletable state within {timeout_s}s "
                f"(last error {last}); it is still billing shard-hours"
            )
        while time.monotonic() < deadline:
            try:
                c.describe_stream_summary(StreamName=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(interval_s)
        raise AssertionError(
            f"stream {name} is still describable {timeout_s}s after DeleteStream returned; leak"
        )

    ctx.on_cleanup(_teardown)

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
    _register_stream_teardown(ctx, c, name)
    _wait_stream_ready(c, name)
    return name

def _get_shards(c, name):
    return c.list_shards(StreamName=name)["Shards"]

CHECK = "merge-shards-combines-adjacent"
GROUP = 'resharding'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MergeShards closes two adjacent open shards and creates exactly one new open child shard.

    The child references both parents (ParentShardId + AdjacentParentShardId) and both parents end up
    closed (they gain an EndingSequenceNumber).
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=2)
    shards = sorted(_get_shards(c, name), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]))
    assert len(shards) == 2, f"expected 2 initial shards, got {len(shards)}"
    shard_a, shard_b = shards[0], shards[1]

    c.merge_shards(
        StreamName=name, ShardToMerge=shard_a["ShardId"], AdjacentShardToMerge=shard_b["ShardId"]
    )
    _wait_stream_ready(c, name)

    def merged_children():
        after = _get_shards(c, name)
        return [
            s for s in after
            if s.get("ParentShardId") == shard_a["ShardId"]
            and s.get("AdjacentParentShardId") == shard_b["ShardId"]
        ]

    merged = _poll(
        merged_children,
        lambda kids: len(kids) == 1,
        timeout_s=90,
        interval_s=3,
        description="one merged child shard after merge",
    )
    assert "EndingSequenceNumber" not in merged[0]["SequenceNumberRange"], "merged child should be open"

    after = _get_shards(c, name)
    a_after = next(s for s in after if s["ShardId"] == shard_a["ShardId"])
    b_after = next(s for s in after if s["ShardId"] == shard_b["ShardId"])
    assert "EndingSequenceNumber" in a_after["SequenceNumberRange"], "parent A should be closed"
    assert "EndingSequenceNumber" in b_after["SequenceNumberRange"], "parent B should be closed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
