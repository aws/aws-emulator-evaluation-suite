"""put-record-binary-blob-byte-equality."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags

CHECK = "put-record-binary-blob-byte-equality"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A raw binary blob (all 256 byte values plus random bytes) round-trips through
    PutRecord -> GetRecords with exact byte equality, no base64 corruption or truncation."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(ctx, kinesis, stream_name)

    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]
    # every possible byte value, twice, plus 256 bytes of true randomness (including
    # embedded null bytes) -- a blob that would break naive text/base64 handling.
    data = bytes(range(256)) * 2 + os.urandom(256)
    kinesis.put_record(StreamName=stream_name, Data=data, PartitionKey="binary-blob")

    records = _wait_for_records(ctx, kinesis, stream_name, shard_id, expected=1)
    assert len(records) == 1, f"expected 1 record, got {len(records)}"
    got = records[0]["Data"]
    assert isinstance(got, (bytes, bytearray)), f"expected bytes/bytearray Data, got {type(got)!r}"
    assert len(got) == len(data), f"length mismatch: {len(got)} != {len(data)}"
    assert bytes(got) == data, "binary payload was corrupted in round-trip"


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
