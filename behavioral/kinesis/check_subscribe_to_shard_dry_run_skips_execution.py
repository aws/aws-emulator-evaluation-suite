"""subscribe-to-shard-dry-run-skips-execution."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "subscribe-to-shard-dry-run-skips-execution"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c2", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard with DryRun=True raises DryRunOperationException and never
    establishes a subscription or consumes the pre-existing record; a real (non-dry-run)
    subscription immediately afterward still sees that same record via TRIM_HORIZON."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-dryrun-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "subscribe-to-shard-dry-run-skips-execution"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, name)

    put = kinesis.put_record(StreamARN=stream_arn, Data=b"dry-run-probe", PartitionKey="pk-1")
    shard_id = put["ShardId"]

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn,
        ConsumerName=consumer_name,
        Tags={"sim2real": "subscribe-to-shard-dry-run-skips-execution"},
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

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

    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    records = []
    for i, event in enumerate(resp["EventStream"]):
        if "SubscribeToShardEvent" in event:
            records.extend(event["SubscribeToShardEvent"]["Records"])
        if records or i >= 4:
            break
    assert len(records) >= 1, "dry run must not have consumed the record; a real subscription must still see it"
    assert records[0]["Data"] == b"dry-run-probe", (
        f"expected the previously-put record data b'dry-run-probe', got {records[0]['Data']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected DryRunOperationException, but the call SUCCEEDED and returned {result!r}")


def _wait_stream_active(ctx, name, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE")


def _wait_consumer_active(ctx, consumer_arn, timeout_s=60.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"]
        if desc["ConsumerStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
