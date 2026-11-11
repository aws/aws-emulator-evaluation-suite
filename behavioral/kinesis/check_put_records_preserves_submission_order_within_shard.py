"""put-records-preserves-submission-order-within-shard."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-records-preserves-submission-order-within-shard"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecords to a single-shard stream assigns distinct sequence numbers, and GetRecords
    replays the records in sequence-number order (PutRecords does not guarantee submission
    order)."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    _wait_stream_active(kinesis, name)
    shard_id = kinesis.list_shards(StreamName=name)["Shards"][0]["ShardId"]

    # Unpadded decimals cross the 9->10 boundary, so payloads are not byte-sorted and a target
    # serving records by payload order instead of sequence order fails the final check.
    n = 25
    entries = [{"Data": f"order-{i}".encode(), "PartitionKey": "same-key"} for i in range(n)]
    submitted_data = [e["Data"] for e in entries]
    assert submitted_data != sorted(submitted_data), (
        f"payload sequence {submitted_data!r} must not already be byte-sorted, or a "
        "sorting emulator would satisfy the order check below by accident"
    )
    put_resp = kinesis.put_records(StreamName=name, Records=entries)
    assert put_resp["FailedRecordCount"] == 0, (
        f"expected FailedRecordCount == 0, got {put_resp['FailedRecordCount']} "
        f"(records={put_resp['Records']})"
    )

    submitted_seqnums = [int(r["SequenceNumber"]) for r in put_resp["Records"]]
    assert len(set(submitted_seqnums)) == n, f"expected {n} distinct sequence numbers, got {submitted_seqnums}"
    by_sequence = [data for _, data in sorted(zip(submitted_seqnums, submitted_data))]

    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    received: list[bytes] = []
    deadline = time.monotonic() + 30
    while len(received) < n and time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        for rec in resp["Records"]:
            received.append(rec["Data"])
        iterator = resp["NextShardIterator"]
        if not resp["Records"]:
            time.sleep(1)

    assert len(received) == n, (
        f"expected {n} records back from GetRecords within the poll deadline, got "
        f"{len(received)}: {received!r}"
    )
    assert received == by_sequence, (
        f"expected GetRecords to replay records in sequence-number order {by_sequence!r}, got {received!r}"
    )


def _wait_stream_active(kinesis, name, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s (last={summary})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
