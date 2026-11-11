"""subscribe-to-shard-dry-run-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-dry-run-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard invoked with DryRun=True fails with DryRunOperationException and never
    establishes an event stream, while an otherwise-identical real subscription actually
    delivers the record previously written to the shard."""
    kinesis = ctx.client("kinesis")
    stream_name, stream_arn = _create_stream(ctx)

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    consumer = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)["Consumer"]
    consumer_arn = consumer["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(kinesis, consumer_arn)

    payload = b"sim2real-behav-subscribe-payload"
    put_resp = kinesis.put_record(StreamARN=stream_arn, Data=payload, PartitionKey="pk-1")
    shard_id = put_resp["ShardId"]


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
    found = False
    deadline = time.monotonic() + 60.0
    for event in resp["EventStream"]:
        shard_event = event.get("SubscribeToShardEvent")
        if shard_event:
            for record in shard_event.get("Records", []):
                if record["Data"] == payload:
                    found = True
                    break
        if found or time.monotonic() >= deadline:
            break
    assert found, "a real (non-dry-run) SubscribeToShard call must deliver the previously written record"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected DryRunOperationException, but the call SUCCEEDED and returned {result!r}"
    )


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _wait_consumer_active(kinesis, consumer_arn, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"][
            "ConsumerStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} never became ACTIVE within {timeout_s}s")


def _create_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-sts-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
