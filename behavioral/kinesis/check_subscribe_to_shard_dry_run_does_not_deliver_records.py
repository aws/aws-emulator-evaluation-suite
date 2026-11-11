"""subscribe-to-shard-dry-run-does-not-deliver-records."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "subscribe-to-shard-dry-run-does-not-deliver-records"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard with DryRun=True fails with DryRunOperationException and delivers nothing,
    while the identical call without DryRun subscribes and delivers the record on the shard."""
    kinesis = ctx.client("kinesis")
    name, stream_arn = _create_active_stream(ctx)

    consumer_name = ctx.unique_name("sim2real-consumer-")
    consumer = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name, Tags={"sim2real": CHECK}
    )
    consumer_arn = consumer["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]
    payload = b"dry-run-target-record"
    kinesis.put_record(StreamARN=stream_arn, Data=payload, PartitionKey="pk")

    code, message = _error(
        lambda: kinesis.subscribe_to_shard(
            ConsumerARN=consumer_arn,
            ShardId=shard_id,
            StartingPosition={"Type": "TRIM_HORIZON"},
            DryRun=True,
        )
    )
    assert code == "DryRunOperationException", f"expected DryRunOperationException, got {code}"
    expected_message = (
        "DryRunOperation validation succeeded while calling SubscribeToShard operation.: "
        "Request would have succeeded, but DryRun flag is set."
    )
    assert message == expected_message, (
        f"dry-run SubscribeToShard message {message!r}, expected {expected_message!r}"
    )

    # Positive control: the identical call without DryRun really does establish a
    # subscription and deliver the record that was sitting on the shard.
    response = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    collected = _collect_subscribed_records(response["EventStream"], min_count=1, timeout_s=45.0)
    assert len(collected) >= 1, (
        "dry run must not have consumed the record; a real subscription must still see it"
    )
    assert collected[0]["Data"] == payload, (
        f"expected the pre-existing record {payload!r}, got {collected[0]['Data']!r}"
    )


def _create_active_stream(ctx, shard_count: int = 1) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinesis-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=shard_count,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        last_status = desc["StreamStatus"]
        if last_status == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"stream never became ACTIVE (last status={last_status})")


def _wait_consumer_active(ctx, consumer_arn: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"]
        last_status = desc["ConsumerStatus"]
        if last_status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"consumer never became ACTIVE (last status={last_status})")


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected DryRunOperationException, but the call SUCCEEDED and returned {result!r}")


def _collect_subscribed_records(event_stream, min_count: int, timeout_s: float = 45.0) -> list[dict]:
    collected: list[dict] = []
    deadline = time.monotonic() + timeout_s
    for event in event_stream:
        shard_event = event.get("SubscribeToShardEvent")
        if shard_event:
            collected.extend(shard_event.get("Records", []))
            if len(collected) >= min_count:
                break
        if time.monotonic() > deadline:
            break
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
