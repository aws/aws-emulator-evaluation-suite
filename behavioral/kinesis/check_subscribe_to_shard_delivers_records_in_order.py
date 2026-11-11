"""subscribe-to-shard-delivers-records-in-order."""
from __future__ import annotations

import threading
import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-delivers-records-in-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The SubscribeToShard enhanced-fanout event stream delivers records in exactly the
    order they were written by PutRecord, and their sequence numbers are increasing."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-")
    stream_arn = _create_and_wait_stream(ctx, stream_name, shard_count=1)

    shards = _list_shards_when_ready(ctx, stream_name)
    assert len(shards) == 1, f"expected 1 shard, got {len(shards)}"
    shard_id = shards[0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    reg = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name, Tags={"sim2real": "ga-depth-kinesis"}
    )
    consumer_arn = reg["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    n = 10
    for i in range(n):
        kinesis.put_record(StreamName=stream_name, Data=f"evt-{i}".encode(), PartitionKey="pk")

    records = _subscribe_and_collect(ctx, consumer_arn, shard_id, expected_count=n, timeout_s=60.0)
    assert len(records) >= n, f"expected at least {n} events delivered, got {len(records)}"
    records = records[:n]

    data = [r["Data"] for r in records]
    assert data == [f"evt-{i}".encode() for i in range(n)], f"delivery order mismatch: {data}"

    seqs = [int(r["SequenceNumber"]) for r in records]
    assert seqs == sorted(seqs), "SubscribeToShard delivered out-of-order sequence numbers"
    assert all(seqs[i] < seqs[i + 1] for i in range(len(seqs) - 1)), (
        "SubscribeToShard sequence numbers not strictly increasing"
    )


def _create_and_wait_stream(ctx, stream_name: str, shard_count: int = 1, timeout_s: float = 300.0) -> str:
    kinesis = ctx.client("kinesis")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_consumer_active(ctx, consumer_arn: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"]
        if desc["ConsumerStatus"] == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s")


def _list_shards_when_ready(ctx, stream_name: str, timeout_s: float = 60.0):
    """Even after describe_stream_summary reports ACTIVE, ListShards can briefly still
    raise ResourceInUseException while the stream finishes provisioning. Retry until it
    succeeds or the timeout elapses."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except kinesis.exceptions.ResourceInUseException as exc:
            last_err = exc
            time.sleep(2)
    raise AssertionError(f"ListShards kept raising ResourceInUseException for {stream_name} within {timeout_s}s: {last_err}")


def _subscribe_and_collect(ctx, consumer_arn: str, shard_id: str, expected_count: int, timeout_s: float = 60.0):
    kinesis = ctx.client("kinesis")
    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    out: list = []
    done = threading.Event()

    def _consume() -> None:
        try:
            for event in resp["EventStream"]:
                sub_event = event.get("SubscribeToShardEvent")
                if sub_event:
                    out.extend(sub_event.get("Records", []))
                    if len(out) >= expected_count:
                        done.set()
                        return
        except Exception:
            done.set()

    t = threading.Thread(target=_consume, daemon=True)
    t.start()
    done.wait(timeout_s)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
