"""split-shard-creates-child-shards."""
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

CHECK = "split-shard-creates-child-shards"
GROUP = 'resharding'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SplitShard closes the parent and yields two open child shards whose sole parent it is."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard = _get_shards(c, name)[0]
    start = int(shard["HashKeyRange"]["StartingHashKey"])
    end = int(shard["HashKeyRange"]["EndingHashKey"])
    midpoint = str(start + (end - start) // 2)

    c.split_shard(StreamName=name, ShardToSplit=shard["ShardId"], NewStartingHashKey=midpoint)
    _wait_stream_ready(c, name)

    def open_shards():
        shards = _get_shards(c, name)
        return [s for s in shards if "EndingSequenceNumber" not in s.get("SequenceNumberRange", {})]

    open_list = _poll(
        open_shards,
        lambda shards: len(shards) == 2,
        timeout_s=90,
        interval_s=3,
        description="two open child shards after split",
    )
    open_ids = {s["ShardId"] for s in open_list}
    assert shard["ShardId"] not in open_ids, (
        f"the split parent {shard['ShardId']} is still open after the split: {open_list!r}"
    )
    parents = {s.get("ParentShardId") for s in open_list}
    assert parents == {shard["ShardId"]}, (
        f"expected both child shards to reference parent {shard['ShardId']} as their sole "
        f"ParentShardId, got {parents} from shards {open_list!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
