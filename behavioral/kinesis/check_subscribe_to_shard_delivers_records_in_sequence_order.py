"""subscribe-to-shard-delivers-records-in-sequence-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-delivers-records-in-sequence-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Records pushed to a single shard via PutRecords are all delivered to an enhanced-fan-out
    SubscribeToShard consumer in increasing sequence-number order; PutRecords guarantees no
    write order, so the payloads are compared order-insensitively."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    summary = _wait_stream_active(kinesis, name)
    stream_arn = summary["StreamARN"]
    shard_id = kinesis.list_shards(StreamName=name)["Shards"][0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-consumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn,
        ConsumerName=consumer_name,
        Tags={"sim2real": "ga-depth-kinesis"},
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(kinesis, consumer_arn)

    n = 20
    entries = [{"Data": f"seq-{i:03d}".encode(), "PartitionKey": "same-key"} for i in range(n)]
    put_resp = kinesis.put_records(StreamName=name, Records=entries)
    assert put_resp["FailedRecordCount"] == 0, (
        f"expected 0 failed PutRecords entries, got {put_resp['FailedRecordCount']}"
    )

    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn, ShardId=shard_id, StartingPosition={"Type": "TRIM_HORIZON"}
    )

    received: list[dict] = []
    deadline = time.monotonic() + 60
    for event in resp["EventStream"]:
        sub_event = event.get("SubscribeToShardEvent")
        if sub_event:
            received.extend(sub_event["Records"])
        if len(received) >= n or time.monotonic() > deadline:
            break

    assert len(received) >= n, (
        f"expected at least {n} records delivered via SubscribeToShard within 60s, got {len(received)}"
    )
    data = [rec["Data"] for rec in received[:n]]
    expected_data = [e["Data"] for e in entries]
    assert data == expected_data or sorted(data) == sorted(expected_data), (
        f"SubscribeToShard delivered other records than written: got {data!r}, expected {expected_data!r}"
    )

    seqs = [int(rec["SequenceNumber"]) for rec in received[:n]]
    assert seqs == sorted(seqs), (
        f"SubscribeToShard delivered non-monotonically-increasing sequence numbers: {seqs}"
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


def _wait_consumer_active(kinesis, consumer_arn, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"][
            "ConsumerStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
