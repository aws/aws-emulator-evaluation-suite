"""put-records-preserves-per-shard-sequence-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-records-preserves-per-shard-sequence-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Records written via PutRecords to a single shard are readable via GetRecords in
    strictly increasing sequence-number order, matching the write order and the
    per-entry sequence numbers returned by PutRecords itself."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-")
    _create_and_wait_stream(ctx, stream_name, shard_count=1)

    shards = kinesis.list_shards(StreamName=stream_name)["Shards"]
    assert len(shards) == 1, f"expected 1 shard, got {len(shards)}"
    shard_id = shards[0]["ShardId"]

    n = 15
    entries = [{"Data": f"rec-{i}".encode(), "PartitionKey": "pk"} for i in range(n)]
    resp = kinesis.put_records(StreamName=stream_name, Records=entries)
    assert resp["FailedRecordCount"] == 0, f"unexpected failures: {resp['Records']}"
    assert all(e["ShardId"] == shard_id for e in resp["Records"]), "all records must land on the single shard"
    written_seqs = [e["SequenceNumber"] for e in resp["Records"]]

    fetched = _collect_records(ctx, stream_name, shard_id, expected_count=n)
    fetched_data = [r["Data"] for r in fetched]
    fetched_seqs = [int(r["SequenceNumber"]) for r in fetched]

    assert fetched_data == [f"rec-{i}".encode() for i in range(n)], (
        f"read-back data order mismatch: {fetched_data}"
    )
    assert fetched_seqs == sorted(fetched_seqs), "sequence numbers not sorted"
    assert all(fetched_seqs[i] < fetched_seqs[i + 1] for i in range(len(fetched_seqs) - 1)), (
        "sequence numbers not strictly increasing"
    )
    assert [str(s) for s in fetched_seqs] == written_seqs, (
        "GetRecords sequence numbers must match the ones PutRecords returned, in order"
    )


def _create_and_wait_stream(ctx, stream_name: str, shard_count: int = 1, timeout_s: float = 300.0) -> str:
    kinesis = ctx.client("kinesis")
    kinesis.create_stream(StreamName=stream_name, ShardCount=shard_count, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


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
