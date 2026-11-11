"""subscribe-to-shard-lease-expires-after-5-minutes."""
from __future__ import annotations

import queue
import threading
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscribe-to-shard-lease-expires-after-5-minutes"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]


# timing:real-time — lease: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShard.html
@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """An enhanced fan-out SubscribeToShard event stream ends on its own after ~5 minutes (200-340 s,
    with at least one event), and a fresh SubscribeToShard afterwards yields an event.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShard.html
    """
    # AWS's "~5 minutes" is not exact, so the wait runs some margin past the nominal 300s.
    lease_s = 300.0
    lease_buffer_s = 30.0
    lease_wait_budget_s = 330.0  # lease_s + lease_buffer_s
    resub_wait_budget_s = 30.0  # EFO pushes an event about every second once caught up

    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-lease-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    shard_id, stream_arn = _stream_ready(ctx, stream_name)

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name, Tags={"sim2real": CHECK}
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(
        lambda: kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerARN=consumer_arn)
    )
    _wait_consumer_active(ctx, stream_arn, consumer_arn, interval_s=1.0)

    # The deadline is anchored to when SubscribeToShard returns, so setup latency is excluded.
    response = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn, ShardId=shard_id, StartingPosition={"Type": "LATEST"}
    )
    start = time.monotonic()
    event_q = _spawn_stream_reader(iter(response["EventStream"]))

    hard_deadline = start + lease_wait_budget_s

    naturally_ended = False
    saw_at_least_one_event = False
    while True:
        remaining = hard_deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            kind, payload = event_q.get(timeout=remaining)
        except queue.Empty:
            break
        if kind == "event":
            if "SubscribeToShardEvent" in payload:
                saw_at_least_one_event = True
            continue
        # "ended": a clean end or a stream-level exception; SDKs may surface expiry either way.
        naturally_ended = True
        break
    elapsed = time.monotonic() - start

    assert saw_at_least_one_event, "never received a single SubscribeToShardEvent before terminating"
    assert naturally_ended, f"event stream did not terminate within {elapsed:.0f}s (expected ~300s lease)"
    assert 200.0 <= elapsed <= 340.0, (
        f"subscription lease lasted {elapsed:.1f}s, expected roughly the documented 5-minute (300s) window"
    )

    resub = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn, ShardId=shard_id, StartingPosition={"Type": "LATEST"}
    )
    resub_q = _spawn_stream_reader(iter(resub["EventStream"]))
    try:
        kind, first_event = resub_q.get(timeout=resub_wait_budget_s)
    except queue.Empty:
        raise AssertionError("resubscription did not yield a usable event within the remaining budget")
    assert kind == "event" and "SubscribeToShardEvent" in first_event, (
        "resubscription did not yield a usable event stream"
    )


def _spawn_stream_reader(stream_iter) -> "queue.Queue[tuple[str, Any]]":
    """Drive an EventStream iterator on a daemon thread, so every caller wait is bounded by
    ``queue.get(timeout=...)`` even though ``next()`` on the stream can block without bound."""
    q: "queue.Queue[tuple[str, Any]]" = queue.Queue()

    def _reader() -> None:
        try:
            for event in stream_iter:
                q.put(("event", event))
        except Exception as exc:  # noqa: BLE001 — any stream-level exception ends the subscription
            q.put(("ended", exc))
            return
        q.put(("ended", None))

    threading.Thread(target=_reader, daemon=True).start()
    return q


def _stream_ready(ctx, stream_name: str, timeout_s: float = 90.0, interval_s: float = 0.5) -> tuple[str, str]:
    """Return (shard_id, stream_arn) once the stream is ACTIVE and its shard is listable."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
            if summary["StreamStatus"] == "ACTIVE":
                shards = kinesis.list_shards(StreamName=stream_name)["Shards"]
                assert len(shards) >= 1, "expected at least one shard"
                return shards[0]["ShardId"], summary["StreamARN"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceInUseException", "ResourceNotFoundException") or (
                time.monotonic() >= deadline
            ):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream {stream_name} did not become ready within {timeout_s}s")
        time.sleep(interval_s)


def _wait_consumer_active(
    ctx, stream_arn: str, consumer_arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(StreamARN=stream_arn, ConsumerARN=consumer_arn)[
            "ConsumerDescription"
        ]["ConsumerStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
