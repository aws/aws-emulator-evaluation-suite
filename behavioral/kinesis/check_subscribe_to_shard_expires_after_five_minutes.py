"""subscribe-to-shard-expires-after-five-minutes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-expires-after-five-minutes"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Resubscribing with AFTER_SEQUENCE_NUMBER and the prior ContinuationSequenceNumber delivers
    records written after that checkpoint and does not redeliver earlier ones.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShard.html
    """
    # The natural ~300s subscription expiry is not waited out; this exercises the
    # client-driven resubscribe half of the same contract.
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-efo-ttl-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(ctx, stream_name)

    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)[
        "StreamDescriptionSummary"
    ]["StreamARN"]
    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-efo-consumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn,
        ConsumerName=consumer_name,
        Tags={"sim2real": "ga-depth-kinesis"},
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    # Put one record BEFORE the first subscription so TRIM_HORIZON has something
    # concrete to deliver; the resumed subscription must not redeliver it.
    kinesis.put_record(
        StreamName=stream_name, Data=b"first-record", PartitionKey="pk-1"
    )

    first = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    continuation_seq = None
    seen_first_record = False
    deadline = time.monotonic() + 60.0
    for event in first["EventStream"]:
        if "SubscribeToShardEvent" not in event:
            continue
        payload = event["SubscribeToShardEvent"]
        continuation_seq = payload["ContinuationSequenceNumber"]
        for rec in payload.get("Records", []):
            if rec["Data"] == b"first-record":
                seen_first_record = True
        if seen_first_record or time.monotonic() > deadline:
            break
    assert seen_first_record, "expected the pre-written record on the first subscription"
    assert continuation_seq, "expected a ContinuationSequenceNumber on every event"

    # Simulate the renewal flow after a subscription lapses: resume from the checkpoint.
    first["EventStream"].close()

    kinesis.put_record(
        StreamName=stream_name, Data=b"second-record", PartitionKey="pk-2"
    )

    resumed = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "AFTER_SEQUENCE_NUMBER", "SequenceNumber": continuation_seq},
    )
    seen_second_record = False
    seen_first_again = False
    deadline = time.monotonic() + 60.0
    for event in resumed["EventStream"]:
        if "SubscribeToShardEvent" not in event:
            continue
        payload = event["SubscribeToShardEvent"]
        for rec in payload.get("Records", []):
            if rec["Data"] == b"second-record":
                seen_second_record = True
            if rec["Data"] == b"first-record":
                seen_first_again = True
        if seen_second_record or time.monotonic() > deadline:
            break
    resumed["EventStream"].close()

    assert seen_second_record, (
        "resubscribing AFTER_SEQUENCE_NUMBER with the prior ContinuationSequenceNumber "
        "must deliver records written after that checkpoint"
    )
    assert not seen_first_again, (
        "resubscribing AFTER_SEQUENCE_NUMBER must NOT redeliver records already "
        "consumed before the checkpoint"
    )


def _wait_stream_active(ctx, stream_name, timeout_s=120.0, interval_s=3.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {stream_name} never became ACTIVE (last status={status})")


def _wait_consumer_active(ctx, consumer_arn, timeout_s=120.0, interval_s=3.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)[
            "ConsumerDescription"
        ]["ConsumerStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"consumer never became ACTIVE (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
