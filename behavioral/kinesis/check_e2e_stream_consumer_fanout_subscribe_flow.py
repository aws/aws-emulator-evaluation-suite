"""e2e-stream-consumer-fanout-subscribe-flow."""
from __future__ import annotations

import threading
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-stream-consumer-fanout-subscribe-flow"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An enhanced fan-out subscriber observes exactly the PutRecords batch (in any order; no order
    is guaranteed). The deregistered consumer and deleted stream then report not-found."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-e2e-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    stream_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None
        if stream_deleted["done"]
        else kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    stream_arn = _wait_stream_active(ctx, stream_name)
    shard_id = _first_shard_id(ctx, stream_arn)

    consumer_name = ctx.unique_name("cons-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name
    )["Consumer"]["ConsumerARN"]
    consumer_deregistered = {"done": False}
    ctx.on_cleanup(
        lambda: None
        if consumer_deregistered["done"]
        else kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
    )
    _wait_consumer_active(ctx, consumer_arn)

    record_count = 12
    payloads = [f"fanout-{i:03d}".encode("utf-8") for i in range(record_count)]
    put_resp = kinesis.put_records(
        StreamName=stream_name,
        Records=[{"Data": p, "PartitionKey": "fixed-key"} for p in payloads],
    )
    assert put_resp["FailedRecordCount"] == 0, (
        f"expected 0 failed records, got {put_resp['FailedRecordCount']}"
    )

    thread, state = _start_subscription(kinesis, consumer_arn, shard_id, "TRIM_HORIZON")
    try:
        collected = _wait_for_records(state, record_count, timeout_s=_budget_s(ctx, 45.0))
        if len(collected) < record_count and _budget_spent(ctx):
            raise TimeoutError(f"{record_count} fan-out records: the run budget ended first; not graded")
        # Hold a fixed 5 s so a stray extra delivery can show up before exactness is asserted.
        _hold_for_extra_deliveries(state, record_count, hold_s=5.0)
    finally:
        _stop_subscription(thread, state)

    assert len(collected) == record_count, (
        f"expected exactly {record_count} records, observed {len(collected)}"
    )
    observed = [rec["Data"] for rec in collected]
    assert observed == payloads or sorted(observed) == sorted(payloads), (
        "the delivered records do not match the written records"
    )

    # Explicit teardown is part of the scenario; on_cleanup is only the fallback.
    kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn)
    consumer_deregistered["done"] = True
    _wait_consumer_gone(kinesis, consumer_arn)
    consumer_code, consumer_message = _error(
        lambda: kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)
    )
    assert consumer_code == "ResourceNotFoundException", "deregistered consumer is still describable"
    expected_consumer_message = (
        f"Consumer {consumer_name} with creation timestamp {consumer_arn.rsplit(':', 1)[1]} "
        f"under stream: {stream_name}, account {ctx.account} not found."
    )
    assert consumer_message == expected_consumer_message, (
        f"expected message {expected_consumer_message!r}, got {consumer_message!r}"
    )

    kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    stream_deleted["done"] = True
    _wait_stream_gone(kinesis, stream_name)
    stream_code, stream_message = _error(lambda: kinesis.describe_stream_summary(StreamName=stream_name))
    assert stream_code == "ResourceNotFoundException", "deleted stream is still describable"
    expected_stream_message = f"Stream {stream_name} under account {ctx.account} not found."
    assert stream_message == expected_stream_message, (
        f"expected message {expected_stream_message!r}, got {stream_message!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"stream {stream_name} to become ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_consumer_active(ctx, consumer_arn: str, timeout_s: float = 60.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"]
        if desc["ConsumerStatus"] == "ACTIVE":
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"consumer {consumer_arn} to become ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s")


def _first_shard_id(ctx, stream_arn: str) -> str:
    kinesis = ctx.client("kinesis")
    shards = kinesis.list_shards(StreamARN=stream_arn)["Shards"]
    if not shards:
        raise AssertionError("stream has no shards")
    return shards[0]["ShardId"]


def _start_subscription(kinesis, consumer_arn: str, shard_id: str, starting_position: str):
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


def _hold_for_extra_deliveries(state: dict[str, Any], expected_count: int, hold_s: float) -> None:
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        if len(state["records"]) > expected_count:
            break
        time.sleep(0.5)


def _stop_subscription(thread: threading.Thread, state: dict[str, Any]) -> None:
    state["stop"].set()
    thread.join(timeout=5.0)


def _wait_consumer_gone(kinesis, consumer_arn: str, timeout_s: float = 60.0) -> None:
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


def _wait_stream_gone(kinesis, stream_name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_summary(StreamName=stream_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} was not removed within {timeout_s}s")


def _error(call) -> tuple[str, str | None]:
    """Call it; return the (code, message) of the ClientError it raises. A success raises."""
    try:
        call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError("expected call to raise ClientError but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
