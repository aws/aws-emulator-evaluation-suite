"""subscribe-to-shard-honors-starting-position-latest."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-honors-starting-position-latest"
GROUP = "data-plane"
SERVICES = ["kinesis"]


@tags("axis:negative-delivery", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard with StartingPosition LATEST only delivers records produced
    after the subscription begins, not records that were already on the shard."""
    kinesis = ctx.client("kinesis")
    name, stream_arn = _create_active_stream(ctx, shard_count=1)

    consumer_name = ctx.unique_name("sim2real-consumer-")
    consumer = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    consumer_arn = consumer["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    shards = kinesis.list_shards(StreamARN=stream_arn)["Shards"]
    assert len(shards) == 1, f"expected exactly one shard for a 1-shard stream, got {len(shards)}"
    shard_id = shards[0]["ShardId"]

    before_payload = b"before-record-prior-to-subscription"
    kinesis.put_record(StreamARN=stream_arn, Data=before_payload, PartitionKey="pk")

    response = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "LATEST"},
    )
    event_iter = iter(response["EventStream"])
    first_event = next(event_iter)  # blocks until the subscription is actually established
    collected: list[dict] = []
    first_shard_event = first_event.get("SubscribeToShardEvent")
    if first_shard_event:
        collected.extend(first_shard_event.get("Records", []))

    after_payload = b"after-record-post-subscription"
    kinesis.put_record(StreamARN=stream_arn, Data=after_payload, PartitionKey="pk")

    deadline = time.monotonic() + 60.0
    for event in event_iter:
        shard_event = event.get("SubscribeToShardEvent")
        if shard_event:
            collected.extend(shard_event.get("Records", []))
            if any(r["Data"] == after_payload for r in collected):
                break
        if time.monotonic() > deadline:
            break

    observed_data = [r["Data"] for r in collected]
    assert after_payload in observed_data, f"post-subscription record never delivered: {observed_data}"
    assert before_payload not in observed_data, (
        f"LATEST subscription incorrectly delivered a pre-existing record: {observed_data}"
    )


def _create_active_stream(ctx, shard_count: int = 1) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinesis-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=shard_count,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real": "ga-depth-kinesis"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
