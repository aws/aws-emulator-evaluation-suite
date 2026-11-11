"""subscribe-to-shard-without-permission-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscribe-to-shard-without-permission-denied"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c4", "cap:c6", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard called by an IAM principal with zero attached permissions is
    denied with AccessDeniedException before any data streams; the same call made by
    the admin caller still succeeds and delivers the previously-put record."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-behav-nosub-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, name)
    _put_record_with_retry(kinesis, stream_arn, b"perm-probe")
    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    consumer_arn = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)[
        "Consumer"
    ]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    user_name = ctx.unique_name("sim2real-behav-nopermuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    unpriv = ctx.client(
        "kinesis",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    code, message = _poll_for_expected_denial(unpriv, consumer_arn, shard_id)
    assert code == "AccessDeniedException", code
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"kinesis:SubscribeToShard on resource: {consumer_arn} because no identity-based policy "
        f"allows the kinesis:SubscribeToShard action"
    )
    assert message == expected_message, (
        f"denied SubscribeToShard message {message!r}, expected {expected_message!r}"
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
    assert len(records) >= 1, f"admin subscribe_to_shard delivered no records: {records!r}"
    assert records[0]["Data"] == b"perm-probe", (
        f"expected the previously-put record b'perm-probe', got {records[0]['Data']!r}"
    )


def _error_code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_for_expected_denial(unpriv_client, consumer_arn, shard_id, timeout_s=30.0):
    """A brand-new IAM access key can take a few seconds to become usable; retry only
    on InvalidClientTokenId/UnrecognizedClientException (key not yet active), never on
    the actual authorization outcome we are trying to observe. Returns ``(code, message)``;
    an unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            result = unpriv_client.subscribe_to_shard(
                ConsumerARN=consumer_arn,
                ShardId=shard_id,
                StartingPosition={"Type": "TRIM_HORIZON"},
            )
        except ClientError as exc:
            last = (_error_code(exc), exc.response.get("Error", {}).get("Message"))
            if last[0] in ("InvalidClientTokenId", "UnrecognizedClientException"):
                time.sleep(2)
                continue
            return last
        raise AssertionError(f"SubscribeToShard succeeded for a principal with no permissions: {result!r}")
    return last


def _put_record_with_retry(kinesis, stream_arn, data, timeout_s=30.0):
    """DescribeStreamSummary reporting ACTIVE does not guarantee the data plane has
    converged for a just-created ON_DEMAND stream; PutRecord can still answer
    ResourceNotFoundException for a few seconds after. Retry only on that specific
    code, never on any other outcome."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kinesis.put_record(StreamARN=stream_arn, Data=data, PartitionKey="pk")
            return
        except ClientError as exc:
            if _error_code(exc) != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


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
