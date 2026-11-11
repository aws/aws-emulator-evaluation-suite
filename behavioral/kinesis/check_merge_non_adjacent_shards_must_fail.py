"""merge-non-adjacent-shards-must-fail."""
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

def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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
    c.add_tags_to_stream(StreamName=name, Tags={"sim2real-check": CHECK})
    _wait_stream_ready(c, name)
    return name

def _get_shards(c, name):
    return c.list_shards(StreamName=name)["Shards"]

CHECK = "merge-non-adjacent-shards-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MergeShards on two non-adjacent shards fails with InvalidArgumentException and its exact
    message, after an adjacent pair merges successfully; no child appears and both stay open."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=4)
    shards = sorted(_get_shards(c, name), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]))
    assert len(shards) == 4, f"expected 4 shards, got {len(shards)}"
    s0, s1, s2, s3 = shards

    # Positive control: s1 and s2 ARE hash-range-adjacent, and the merge must succeed.
    c.merge_shards(StreamName=name, ShardToMerge=s1["ShardId"], AdjacentShardToMerge=s2["ShardId"])
    _wait_stream_ready(c, name)

    def merged_control_child():
        after = _get_shards(c, name)
        return [
            s for s in after
            if s.get("ParentShardId") == s1["ShardId"] and s.get("AdjacentParentShardId") == s2["ShardId"]
        ]

    control = _poll(
        merged_control_child, lambda kids: len(kids) == 1, timeout_s=90, interval_s=3,
        description="one merged child shard after the positive-control merge",
    )
    assert "EndingSequenceNumber" not in control[0]["SequenceNumberRange"], (
        "the positive-control merge produced a closed child; it should be open"
    )

    # s0 and s3 are the original outer shards. The control merge's child now separates them in
    # hash-range order, so they remain non-adjacent -- merging them must be rejected.
    error = _client_error(lambda: c.merge_shards(
        StreamName=name, ShardToMerge=s0["ShardId"], AdjacentShardToMerge=s3["ShardId"]
    ))
    assert error.get("Code") == "InvalidArgumentException", (
        f"expected InvalidArgumentException, got {error.get('Code')}"
    )
    expected_message = (
        f"Shards {s0['ShardId']} and {s3['ShardId']} in stream {name} under account {ctx.account} "
        "are not an adjacent pair of shards eligible for merging"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect-absent, via an independent read: no child shard from the rejected merge, and both
    # s0 and s3 are still open.
    after = _get_shards(c, name)
    assert not any(
        s.get("ParentShardId") == s0["ShardId"] and s.get("AdjacentParentShardId") == s3["ShardId"]
        for s in after
    ), "the rejected non-adjacent merge produced a child shard anyway"
    s0_after = next(s for s in after if s["ShardId"] == s0["ShardId"])
    s3_after = next(s for s in after if s["ShardId"] == s3["ShardId"])
    assert "EndingSequenceNumber" not in s0_after["SequenceNumberRange"], (
        "s0 should remain open after the rejected merge"
    )
    assert "EndingSequenceNumber" not in s3_after["SequenceNumberRange"], (
        "s3 should remain open after the rejected merge"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
