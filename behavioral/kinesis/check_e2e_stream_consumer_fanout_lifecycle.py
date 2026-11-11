"""e2e-stream-consumer-fanout-lifecycle."""
from __future__ import annotations

import queue
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-stream-consumer-fanout-lifecycle"
GROUP = "e2e"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full enhanced fan-out lifecycle: create a stream, register a consumer, subscribe to
    its shard, write records, observe them delivered over the live subscription, then
    deregister the consumer and delete the stream."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"sim2real": CHECK})
    _wait_stream_active(ctx, kinesis, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-consumer-")
    consumer_arn = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)[
        "Consumer"
    ]["ConsumerARN"]
    ctx.on_cleanup(lambda: _safe_deregister(kinesis, consumer_arn))
    kinesis.tag_resource(ResourceARN=consumer_arn, Tags={"sim2real": CHECK})
    _wait_consumer_active(ctx, kinesis, consumer_arn)

    events_q: "queue.Queue" = queue.Queue()
    stop_flag = threading.Event()

    def _consume():
        try:
            resp = kinesis.subscribe_to_shard(
                ConsumerARN=consumer_arn,
                ShardId=shard_id,
                StartingPosition={"Type": "TRIM_HORIZON"},
            )
            for event in resp["EventStream"]:
                events_q.put(event)
                if stop_flag.is_set():
                    break
        except Exception as exc:  # noqa: BLE001 - surfaced to main thread
            events_q.put(exc)

    thread = threading.Thread(target=_consume, daemon=True)
    thread.start()

    # the first event on a fresh subscription is a SubscribeToShardEvent confirming the
    # subscription is live (with zero records, since the stream is brand new).
    initial = events_q.get(timeout=30)
    if isinstance(initial, Exception):
        raise AssertionError(f"SubscribeToShard failed to establish: {initial}")
    assert "SubscribeToShardEvent" in initial, f"unexpected first event: {initial!r}"
    initial_records = initial["SubscribeToShardEvent"].get("Records", [])
    assert not initial_records, (
        f"fresh subscription's confirmation event carried records before any write: "
        f"{initial_records!r}"
    )

    payloads = [f"fanout-record-{i}".encode() for i in range(3)]
    kinesis.put_records(
        StreamName=stream_name,
        Records=[{"Data": p, "PartitionKey": f"pk-{i}"} for i, p in enumerate(payloads)],
    )

    observed: list = []
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and len(observed) < len(payloads):
        try:
            event = events_q.get(timeout=5)
        except queue.Empty:
            continue
        if isinstance(event, Exception):
            raise AssertionError(f"subscription failed mid-stream: {event}")
        if "SubscribeToShardEvent" in event:
            observed.extend(event["SubscribeToShardEvent"].get("Records", []))

    stop_flag.set()
    thread.join(timeout=10)

    observed_data = [r["Data"] for r in observed]
    # PutRecords does not guarantee record order, so delivery order is not graded.
    assert observed_data == payloads or sorted(observed_data) == sorted(payloads), (
        f"enhanced fan-out subscription did not deliver exactly the written records: "
        f"expected {payloads}, observed {observed_data}"
    )

    # explicit teardown as part of the flow (not just cleanup safety-net)
    kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
    _wait_consumer_gone(ctx, kinesis, consumer_arn)

    kinesis.delete_stream(StreamName=stream_name)
    _wait_stream_gone(ctx, kinesis, stream_name)


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


def _wait_stream_gone(ctx, kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_summary(StreamName=stream_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} was not removed within {timeout_s}s")


def _wait_consumer_active(ctx, kinesis, consumer_arn, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"][
            "ConsumerStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s")


def _wait_consumer_gone(ctx, kinesis, consumer_arn, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} was not removed within {timeout_s}s")


def _safe_deregister(kinesis, consumer_arn):
    try:
        kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_stream(kinesis, stream_name):
    try:
        kinesis.delete_stream(StreamName=stream_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
