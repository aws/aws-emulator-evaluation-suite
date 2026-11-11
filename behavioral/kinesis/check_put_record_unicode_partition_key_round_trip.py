"""put-record-unicode-partition-key-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-record-unicode-partition-key-round-trip"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-byte unicode partition key survives PutRecord -> GetRecords unchanged."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(ctx, kinesis, stream_name)

    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]
    partition_key = "パーティション-キー-🎉-données-ключ"
    data = b"unicode-partition-key-payload"
    kinesis.put_record(StreamName=stream_name, Data=data, PartitionKey=partition_key)

    records = _wait_for_records(ctx, kinesis, stream_name, shard_id, expected=1)
    assert len(records) == 1, f"expected 1 record, got {len(records)}"
    assert records[0]["PartitionKey"] == partition_key, (
        f"partition key corrupted: {records[0]['PartitionKey']!r} != {partition_key!r}"
    )
    assert records[0]["Data"] == data, f"data corrupted: {records[0]['Data']!r} != {data!r}"


def _wait_stream_active(ctx, kinesis, stream_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_for_records(ctx, kinesis, stream_name, shard_id, expected, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        records = kinesis.get_records(ShardIterator=iterator, Limit=100)["Records"]
        if len(records) >= expected:
            return records
        time.sleep(2)
    raise AssertionError(f"expected {expected} record(s), never observed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
