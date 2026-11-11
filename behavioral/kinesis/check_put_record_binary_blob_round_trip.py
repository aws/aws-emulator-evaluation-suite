"""put-record-binary-blob-round-trip."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Arbitrary non-UTF8 binary data written via PutRecord is returned
    unchanged (no re-encoding/truncation) by GetRecords."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(ctx, name)

    # All 256 byte values plus random bytes plus explicit invalid-UTF8 sequences.
    payload = bytes(range(256)) + os.urandom(2048) + b"\xff\xfe\x00\x80\xc0\xc1"

    put = _put_record_when_ready(kinesis, name, payload)
    shard_id = put["ShardId"]

    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    records = _poll_for_records(kinesis, iterator, expected_count=1, timeout_s=30.0)
    assert len(records) == 1, f"expected exactly 1 record, got {len(records)}"
    assert records[0]["Data"] == payload, (
        f"binary payload corrupted in round trip: expected {len(payload)} bytes, "
        f"got {records[0]['Data'][:32]!r}... ({len(records[0]['Data'])} bytes)"
    )
    assert len(records[0]["Data"]) == len(payload), (
        f"expected {len(payload)} bytes back, got {len(records[0]['Data'])}"
    )


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE within {timeout_s}s")


def _put_record_when_ready(kinesis, name: str, payload: bytes, timeout_s: float = 30.0):
    """DescribeStreamSummary reporting ACTIVE precedes full data-plane routing
    readiness by a few seconds on real AWS; PutRecord can still answer
    ResourceNotFoundException immediately afterward. Retry within a bounded window
    rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.put_record(StreamName=name, Data=payload, PartitionKey="binary-blob")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(1)


def _poll_for_records(kinesis, shard_iterator: str, expected_count: int, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    iterator = shard_iterator
    collected: list = []
    while time.monotonic() < deadline and len(collected) < expected_count:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        collected.extend(resp["Records"])
        iterator = resp["NextShardIterator"]
        if len(collected) < expected_count:
            time.sleep(1)
    if len(collected) < expected_count:
        raise AssertionError(f"expected {expected_count} records, got {len(collected)}")
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
