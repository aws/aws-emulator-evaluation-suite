"""e2e-enhanced-fanout-consumer-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-enhanced-fanout-consumer-lifecycle"
GROUP = "e2e"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An enhanced fan-out consumer receives a record via SubscribeToShard; after deregistration,
    SubscribeToShard against it fails with ResourceNotFoundException and its exact message."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-efo-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    summary = _wait_stream_active(kinesis, stream_name)
    stream_arn = summary["StreamARN"]

    consumer_name = ctx.unique_name("sim2real-behav-efoconsumer-")
    reg = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    consumer_arn = reg["Consumer"]["ConsumerARN"]
    _wait_consumer_active(kinesis, stream_arn, consumer_arn)

    payload = b"sim2real-efo-payload"
    kinesis.put_record(StreamARN=stream_arn, Data=payload, PartitionKey="pk-efo")

    shards = kinesis.list_shards(StreamARN=stream_arn)["Shards"]
    assert shards, f"stream {stream_name} reported no shards"
    shard_id = shards[0]["ShardId"]
    found = _subscribe_and_collect(kinesis, consumer_arn, shard_id, expected_payload=payload)
    assert found, (
        f"expected payload {payload!r} was never observed on the EFO subscription for "
        f"consumer {consumer_arn}"
    )

    kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerARN=consumer_arn)
    _wait_consumer_gone(kinesis, stream_arn, consumer_arn)

    code, message = _subscribe_error(kinesis, consumer_arn, shard_id)
    assert code == "ResourceNotFoundException", (
        f"expected SubscribeToShard against deregistered consumer {consumer_arn} to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    creation_timestamp = consumer_arn.rsplit(":", 1)[1]
    expected_message = (
        f"Consumer {consumer_name} with creation timestamp {creation_timestamp} under stream: "
        f"{stream_name}, account {ctx.account} not found."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE, last={summary}")


def _wait_consumer_active(kinesis, stream_arn: str, consumer_arn: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerARN=consumer_arn
        )["ConsumerDescription"]["ConsumerStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} never became ACTIVE, last={status}")


def _wait_consumer_gone(kinesis, stream_arn: str, consumer_arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_consumer(StreamARN=stream_arn, ConsumerARN=consumer_arn)
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} was never fully deregistered")


def _subscribe_and_collect(kinesis, consumer_arn: str, shard_id: str, expected_payload: bytes) -> bool:
    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    for i, event in enumerate(resp["EventStream"]):
        shard_event = event.get("SubscribeToShardEvent")
        if shard_event:
            for record in shard_event.get("Records", []):
                if bytes(record["Data"]) == expected_payload:
                    return True
        if i >= 20:
            break
    return False


def _subscribe_error(kinesis, consumer_arn: str, shard_id: str) -> tuple[str, str | None]:
    """The (code, message) SubscribeToShard is refused with. A success raises."""
    try:
        resp = kinesis.subscribe_to_shard(
            ConsumerARN=consumer_arn,
            ShardId=shard_id,
            StartingPosition={"Type": "LATEST"},
        )
        # consume the stream a bit in case the error arrives as an event-stream error
        for _ in resp["EventStream"]:
            break
    except Exception as exc:  # noqa: BLE001
        code = _error_code(exc)
        if code is not None:
            return code, exc.response.get("Error", {}).get("Message")
        raise
    raise AssertionError(
        f"SubscribeToShard unexpectedly succeeded against deregistered consumer {consumer_arn}"
    )


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if response is None:
        return None
    return response.get("Error", {}).get("Code")


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
