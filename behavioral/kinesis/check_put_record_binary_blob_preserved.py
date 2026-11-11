"""put-record-binary-blob-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-record-binary-blob-preserved"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An arbitrary non-UTF8 binary payload written via PutRecord is returned byte-for-byte
    identical via GetRecords, with no re-encoding loss."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-binary-")
    _wait_for_shard_capacity(kinesis)
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    _wait_for_stream_active(ctx, name)

    shard_id = kinesis.list_shards(StreamName=name)["Shards"][0]["ShardId"]
    shard_iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    # every possible byte value, plus a repeated invalid-UTF8 lead-byte run
    payload = bytes(range(256)) + (b"\xff\xfe\x80\xc0" * 8)
    kinesis.put_record(StreamName=name, Data=payload, PartitionKey="binary-blob")

    records = _poll_for_records(ctx, shard_iterator, expected=1)
    assert records[0]["Data"] == payload, "binary payload was altered in the PutRecord/GetRecords round trip"


def _wait_for_shard_capacity(kinesis, needed=1, timeout_s=90.0):
    """Poll DescribeLimits until the account has at least `needed` free shards.
    DeleteStream releases OpenShardCount eventually, so recently deleted streams can
    briefly hold capacity, and a momentary shortfall is not itself a fidelity finding."""
    deadline = time.monotonic() + timeout_s
    limits = None
    while time.monotonic() < deadline:
        limits = kinesis.describe_limits()
        if limits["ShardLimit"] - limits["OpenShardCount"] >= needed:
            return limits
        time.sleep(3.0)
    raise AssertionError(
        f"shared account had no free shard capacity within {timeout_s}s "
        f"(ShardLimit={limits['ShardLimit'] if limits else '?'}, "
        f"OpenShardCount={limits['OpenShardCount'] if limits else '?'}); "
        "likely another large stream elsewhere in the account is still deleting"
    )


def _wait_for_stream_active(ctx, name, timeout_s=180.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"stream {name} did not reach ACTIVE within {timeout_s}s")


def _poll_for_records(ctx, shard_iterator, expected, timeout_s=60.0):
    kinesis = ctx.client("kinesis")
    records: list = []
    iterator = shard_iterator
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(records) < expected:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        records.extend(resp["Records"])
        iterator = resp["NextShardIterator"]
        if len(records) < expected:
            time.sleep(2.0)
    if len(records) < expected:
        raise AssertionError(f"expected {expected} records, got {len(records)} within {timeout_s}s")
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
