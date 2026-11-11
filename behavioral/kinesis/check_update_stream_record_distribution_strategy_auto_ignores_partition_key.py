"""update-stream-record-distribution-strategy-auto-ignores-partition-key."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-record-distribution-strategy-auto-ignores-partition-key"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """USER_PARTITION_KEY routes one key to its MD5 shard; switching to AUTO spreads that key across
    shards without moving earlier records; switching back restores the hash routing."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinrds-")
    kinesis.create_stream(
        StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"}, Tags={"sim2real": "kinrds"}
    )
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, name))
    summary = _wait_stream_status(ctx, name, {"ACTIVE"}, timeout_s=180)
    stream_arn = summary["StreamARN"]
    open_shards = _open_shards(kinesis, stream_arn)
    assert len(open_shards) >= 2, (
        f"an on-demand stream opened with {len(open_shards)} shard(s); need at least 2 for this "
        "check to tell USER_PARTITION_KEY routing apart from AUTO routing"
    )

    partition_key = ctx.unique_name("sim2real-kinrds-pk-")
    hashed_shard = _shard_for_key(open_shards, partition_key)

    before_shards = set()
    before_records = {}
    for i in range(8):
        data = f"before-{i}"
        resp = kinesis.put_record(
            StreamName=name, Data=data.encode(), PartitionKey=partition_key
        )
        before_shards.add(resp["ShardId"])
        before_records[data] = resp["ShardId"]
    assert before_shards == {hashed_shard}, (
        f"USER_PARTITION_KEY (the default strategy) sent partition key {partition_key!r} to "
        f"shards {sorted(before_shards)}; it must route every record for one key to the shard "
        f"whose HashKeyRange holds the key's MD5 hash, {hashed_shard!r}"
    )

    kinesis.update_stream_record_distribution_strategy(
        StreamARN=stream_arn, RecordDistributionStrategy="AUTO"
    )

    after_shards = _poll_until_multiple_shards(
        kinesis, name, partition_key, min_distinct=2, timeout_s=120
    )
    assert len(after_shards) >= 2, (
        f"after switching to AUTO, PutRecord calls carrying the same partition key "
        f"{partition_key!r} still landed on a single shard {sorted(after_shards)}; AUTO must "
        "ignore PartitionKey and distribute across shards"
    )

    # The switch governs new writes only: every record written before it is still read
    # back from the shard PutRecord assigned it, and from no other shard.
    located = _locate_records(kinesis, stream_arn, sorted(open_shards), set(before_records))
    assert located == {data: {shard} for data, shard in before_records.items()}, (
        f"records written under USER_PARTITION_KEY must stay on their assigned shard "
        f"{hashed_shard!r} after the switch to AUTO; read back {located}"
    )

    kinesis.update_stream_record_distribution_strategy(
        StreamARN=stream_arn, RecordDistributionStrategy="USER_PARTITION_KEY"
    )
    restored = _poll_until_consistent_routing(
        kinesis, name, partition_key, run_length=8, timeout_s=120
    )
    assert restored == [hashed_shard] * 8, (
        f"after switching back to USER_PARTITION_KEY, consecutive PutRecord calls carrying "
        f"{partition_key!r} must all land on the hash-assigned shard {hashed_shard!r} again; "
        f"the last run landed on {restored}"
    )


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] in target_statuses:
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={summary})")


def _open_shards(kinesis, stream_arn: str) -> dict:
    """{shard id: (starting hash key, ending hash key)} for every open shard."""
    shards = {}
    kwargs = {"StreamARN": stream_arn}
    while True:
        page = kinesis.list_shards(**kwargs)
        for shard in page["Shards"]:
            if "EndingSequenceNumber" not in shard["SequenceNumberRange"]:
                hash_range = shard["HashKeyRange"]
                shards[shard["ShardId"]] = (
                    int(hash_range["StartingHashKey"]), int(hash_range["EndingHashKey"])
                )
        next_token = page.get("NextToken")
        if not next_token:
            return shards
        kwargs = {"NextToken": next_token}


def _shard_for_key(open_shards: dict, partition_key: str) -> str:
    """The open shard whose HashKeyRange holds the 128-bit MD5 of the partition key."""
    hashed = int(hashlib.md5(partition_key.encode("utf-8")).hexdigest(), 16)
    owners = [sid for sid, (lo, hi) in open_shards.items() if lo <= hashed <= hi]
    assert len(owners) == 1, (
        f"exactly one open shard must own hash {hashed} of {partition_key!r}, got {owners} "
        f"from {open_shards}"
    )
    return owners[0]


def _locate_records(kinesis, stream_arn: str, shard_ids, wanted: set) -> dict:
    """{record data: set of shard ids it was read back from}, for the wanted data values."""
    located = {}
    for shard_id in shard_ids:
        iterator = kinesis.get_shard_iterator(
            StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        for _ in range(20):
            page = kinesis.get_records(StreamARN=stream_arn, ShardIterator=iterator, Limit=1000)
            for record in page["Records"]:
                data = record["Data"].decode()
                if data in wanted:
                    located.setdefault(data, set()).add(shard_id)
            iterator = page.get("NextShardIterator")
            if not iterator or (not page["Records"] and page.get("MillisBehindLatest") == 0):
                break
            time.sleep(0.25)
    return located


def _poll_until_multiple_shards(kinesis, name, partition_key, min_distinct, timeout_s):
    """Keep issuing PutRecord with the fixed partition key until the strategy switch is
    observably in effect (distinct shards seen), or the deadline passes. The switch has no
    describable status to poll directly, so the write path itself is the observable condition."""
    deadline = time.monotonic() + timeout_s
    seen = set()
    i = 0
    while time.monotonic() < deadline:
        resp = kinesis.put_record(
            StreamName=name, Data=f"after-{i}".encode(), PartitionKey=partition_key
        )
        seen.add(resp["ShardId"])
        if len(seen) >= min_distinct:
            return seen
        i += 1
        time.sleep(0.5)
    return seen



def _poll_until_consistent_routing(kinesis, name, partition_key, run_length, timeout_s):
    """Keep issuing PutRecord with the fixed partition key until the last run_length writes all
    landed on one shard, or the deadline passes; returns the shard ids of the last run_length."""
    deadline = time.monotonic() + timeout_s
    recent = []
    i = 0
    while time.monotonic() < deadline:
        resp = kinesis.put_record(
            StreamName=name, Data=f"restored-{i}".encode(), PartitionKey=partition_key
        )
        recent = (recent + [resp["ShardId"]])[-run_length:]
        if len(recent) == run_length and len(set(recent)) == 1:
            return recent
        i += 1
        time.sleep(0.5)
    return recent

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
