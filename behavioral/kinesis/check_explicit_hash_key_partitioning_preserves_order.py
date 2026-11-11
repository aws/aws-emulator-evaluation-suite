"""explicit-hash-key-partitioning-preserves-order."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "explicit-hash-key-partitioning-preserves-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


def _pk_hash(partition_key: str) -> int:
    """The explicit hash key Kinesis derives from a partition key: MD5 as a 128-bit int."""
    return int(hashlib.md5(partition_key.encode("utf-8")).hexdigest(), 16)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Records written with the same ExplicitHashKey all route to the shard whose
    HashKeyRange contains that key -- even when the partition key's own hash would route
    elsewhere -- and are retrievable via GetRecords in write order."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-")
    _create_and_wait_stream(ctx, stream_name, shard_count=2)

    shards = _list_shards_when_ready(kinesis, stream_name)
    assert len(shards) == 2, f"expected 2 shards, got {len(shards)}"
    target_shard, other_shard = shards[0], shards[1]
    shard_id = target_shard["ShardId"]
    explicit_hash_key = target_shard["HashKeyRange"]["StartingHashKey"]

    # A partition key whose OWN hash lands in the OTHER shard, so a target that ignores
    # ExplicitHashKey and routes by the partition key alone cannot pass this by coincidence.
    partition_key = next(
        (
            candidate
            for candidate in (f"pk-{i:03d}" for i in range(200))
            if int(other_shard["HashKeyRange"]["StartingHashKey"])
            <= _pk_hash(candidate)
            <= int(other_shard["HashKeyRange"]["EndingHashKey"])
        ),
        None,
    )
    assert partition_key is not None, (
        f"no candidate partition key hashes into the non-target shard "
        f"{other_shard['ShardId']!r} range {other_shard['HashKeyRange']!r}; fixture cannot discriminate"
    )
    assert not (
        int(target_shard["HashKeyRange"]["StartingHashKey"])
        <= _pk_hash(partition_key)
        <= int(target_shard["HashKeyRange"]["EndingHashKey"])
    ), (
        f"setup invalid: partition key {partition_key!r} also hashes into the target shard "
        f"{shard_id!r}, so it cannot show ExplicitHashKey overriding it"
    )

    n = 8
    written_seqs = []
    for i in range(n):
        resp = kinesis.put_record(
            StreamName=stream_name,
            Data=f"hk-{i}".encode(),
            PartitionKey=partition_key,
            ExplicitHashKey=explicit_hash_key,
        )
        assert resp["ShardId"] == shard_id, (
            f"record {i} with ExplicitHashKey={explicit_hash_key} (PartitionKey {partition_key!r} "
            f"naturally hashes to the other shard {other_shard['ShardId']!r}) landed on "
            f"{resp['ShardId']!r}, expected the explicit-hash-key-owning shard {shard_id!r}"
        )
        written_seqs.append(resp["SequenceNumber"])

    fetched = _collect_records(ctx, stream_name, shard_id, expected_count=n)
    fetched_data = [r["Data"] for r in fetched]
    fetched_seqs = [r["SequenceNumber"] for r in fetched]

    assert fetched_data == [f"hk-{i}".encode() for i in range(n)], (
        f"read-back data order mismatch: {fetched_data}"
    )
    assert fetched_seqs == written_seqs, "read-back sequence numbers must match write order exactly"


def _create_and_wait_stream(ctx, stream_name: str, shard_count: int = 1, timeout_s: float = 300.0) -> str:
    kinesis = ctx.client("kinesis")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(lambda: _delete_and_confirm_gone(kinesis, stream_name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _list_shards_when_ready(kinesis, stream_name: str, timeout_s: float = 60.0):
    """DescribeStreamSummary can report ACTIVE slightly before ListShards is consistent with
    it; real AWS answers ListShards with ResourceInUseException for a short window after that,
    which is a retry condition, not a failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(1)


def _delete_and_confirm_gone(kinesis, stream_name: str, timeout_s: float = 120.0) -> None:
    kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_summary(StreamName=stream_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"stream {stream_name} is still describable {timeout_s}s after DeleteStream returned; leak"
    )


def _collect_records(ctx, stream_name: str, shard_id: str, expected_count: int, timeout_s: float = 60.0):
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=1000)
        out.extend(resp["Records"])
        iterator = resp.get("NextShardIterator")
        if iterator is None:
            break
        if not resp["Records"]:
            time.sleep(1)
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} records, got {len(out)} within {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
