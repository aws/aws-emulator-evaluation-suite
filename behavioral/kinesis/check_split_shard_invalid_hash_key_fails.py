"""split-shard-invalid-hash-key-fails."""
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

def _error(fn):
    try:
        resp = fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if not code:
            raise AssertionError(f"call raised {type(exc).__name__} with no AWS error code: {exc}")
        return code, exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"call succeeded unexpectedly and returned {resp!r}, expected a rejection")

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

CHECK = "split-shard-invalid-hash-key-fails"
GROUP = 'resharding'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SplitShard at the parent's own StartingHashKey (an empty low child) MUST fail, leaving
    the shard unsplit; the identical parent split at its midpoint MUST then succeed."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard = _get_shards(c, name)[0]
    shard_id = shard["ShardId"]
    lo = int(shard["HashKeyRange"]["StartingHashKey"])
    hi = int(shard["HashKeyRange"]["EndingHashKey"])

    code, message = _error(
        lambda: c.split_shard(
            StreamName=name, ShardToSplit=shard_id, NewStartingHashKey=str(lo)
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_message = (
        f"NewStartingHashKey {lo} used in SplitShard() on shard {shard_id} in stream {name} under "
        f"account {ctx.account} is not both greater than one plus the shard's StartingHashKey "
        f"{lo} and less than the shard's EndingHashKey {hi}."
    )
    assert message == expected_message, (
        f"SplitShard at the parent's StartingHashKey answered {message!r}, expected {expected_message!r}"
    )

    # ---- effect absent: an independent read shows the shard map untouched by the rejection --- #
    still = _get_shards(c, name)
    assert [s["ShardId"] for s in still] == [shard_id], (
        f"a rejected SplitShard changed the shard map to {[s['ShardId'] for s in still]!r}, "
        f"expected only {shard_id!r}"
    )
    assert still[0]["SequenceNumberRange"].get("EndingSequenceNumber") is None, (
        f"a rejected SplitShard closed the parent shard: {still[0]['SequenceNumberRange']!r}"
    )

    # ---- positive control: the identical parent split at a valid hash key succeeds ----------- #
    mid = (lo + hi) // 2
    c.split_shard(StreamName=name, ShardToSplit=shard_id, NewStartingHashKey=str(mid))
    children = _poll(
        lambda: [s for s in _get_shards(c, name) if s.get("ParentShardId") == shard_id],
        lambda kids: len(kids) == 2,
        90, 2, f"parent {shard_id} split into two children",
    )
    ranges = sorted(
        (int(s["HashKeyRange"]["StartingHashKey"]), int(s["HashKeyRange"]["EndingHashKey"]))
        for s in children
    )
    assert ranges == [(lo, mid - 1), (mid, hi)], (
        f"the control split's children cover {ranges!r}, expected {[(lo, mid - 1), (mid, hi)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
