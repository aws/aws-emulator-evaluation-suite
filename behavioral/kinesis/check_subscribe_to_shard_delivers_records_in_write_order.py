"""subscribe-to-shard-delivers-records-in-write-order."""
from __future__ import annotations

import threading
import time
from typing import Any

from behavioral_harness import tags

CHECK = "subscribe-to-shard-delivers-records-in-write-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard on a single-shard stream delivers exactly the PutRecords-written records
    in strictly increasing sequence-number order; payloads are compared order-insensitively
    because PutRecords does not guarantee write order."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-order-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    stream_arn = _wait_stream_active(ctx, stream_name)
    shard_id = _first_shard_id(ctx, stream_arn)

    consumer_name = ctx.unique_name("cons-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    record_count = 25
    payloads = [f"order-{i:04d}".encode("utf-8") for i in range(record_count)]
    put_resp = kinesis.put_records(
        StreamName=stream_name,
        Records=[{"Data": p, "PartitionKey": "fixed-key"} for p in payloads],
    )
    assert put_resp["FailedRecordCount"] == 0, "PutRecords reported failures"

    thread, state = _start_subscription(kinesis, consumer_arn, shard_id, "TRIM_HORIZON")
    try:
        collected = _wait_for_records(state, record_count, timeout_s=45.0)
        assert len(collected) >= record_count, (
            f"expected at least {record_count} records via subscription, got {len(collected)}"
        )
        observed = [rec["Data"] for rec in collected[:record_count]]
        assert observed == payloads or sorted(observed) == sorted(payloads), (
            "the delivered records do not match the written records"
        )
        # sequence numbers must also be strictly increasing for a single shard
        seq_numbers = [int(rec["SequenceNumber"]) for rec in collected[:record_count]]
        assert all(seq_numbers[i] < seq_numbers[i + 1] for i in range(len(seq_numbers) - 1)), (
            f"sequence numbers were not strictly increasing: {seq_numbers}"
        )
    finally:
        _stop_subscription(thread, state)


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_consumer_active(ctx, consumer_arn: str, timeout_s: float = 60.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"]
        if desc["ConsumerStatus"] == "ACTIVE":
            return
        time.sleep(1)
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s")


def _first_shard_id(ctx, stream_arn: str) -> str:
    kinesis = ctx.client("kinesis")
    shards = kinesis.list_shards(StreamARN=stream_arn)["Shards"]
    if not shards:
        raise AssertionError("stream has no shards")
    return shards[0]["ShardId"]


def _start_subscription(kinesis, consumer_arn: str, shard_id: str, starting_position: str):
    """Start an enhanced fan-out subscription in a background thread; return (thread, state)
    where state["records"] accumulates delivered records."""
    state: dict[str, Any] = {
        "records": [],
        "errors": [],
        "stop": threading.Event(),
        "started": threading.Event(),
    }

    def worker() -> None:
        try:
            resp = kinesis.subscribe_to_shard(
                ConsumerARN=consumer_arn,
                ShardId=shard_id,
                StartingPosition={"Type": starting_position},
            )
            state["started"].set()
            for event in resp["EventStream"]:
                if state["stop"].is_set():
                    break
                sub_event = event.get("SubscribeToShardEvent")
                if sub_event:
                    state["records"].extend(sub_event.get("Records", []))
        except Exception as exc:  # noqa: BLE001
            state["errors"].append(exc)
            state["started"].set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not state["started"].wait(timeout=15.0):
        raise AssertionError("subscription did not start within 15s")
    if state["errors"]:
        raise state["errors"][0]
    return thread, state


def _wait_for_records(state: dict[str, Any], min_count: int, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if state["errors"]:
            raise state["errors"][0]
        if len(state["records"]) >= min_count:
            return state["records"]
        time.sleep(0.3)
    return state["records"]


def _stop_subscription(thread: threading.Thread, state: dict[str, Any]) -> None:
    state["stop"].set()
    thread.join(timeout=5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
