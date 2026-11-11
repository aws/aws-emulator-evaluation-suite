"""subscribe-to-shard-without-permission-must-be-denied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-without-permission-must-be-denied"
GROUP = "overly-permissive"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c6", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubscribeToShard by an IAM user with no policies fails with AccessDeniedException, while
    the permitted caller subscribing to the same consumer and shard receives a real event."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    stream_name = ctx.unique_name("sim2real-behav-kinesis-substream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _wait_stream_active(ctx, stream_name)

    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-behav-kinesis-consumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(ctx, consumer_arn)

    user_name = ctx.unique_name("sim2real-behav-kinesis-nouser-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key["AccessKeyId"])
    )

    low_priv = ctx.client(
        "kinesis",
        creds={
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        },
    )

    code, message = _wait_for_expected_denial(
        low_priv, consumer_arn, shard_id, expected_code="AccessDeniedException", timeout_s=45.0
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"kinesis:SubscribeToShard on resource: {consumer_arn} because no identity-based policy "
        f"allows the kinesis:SubscribeToShard action"
    )
    assert message == expected_message, (
        f"denied SubscribeToShard message {message!r}, expected {expected_message!r}"
    )

    # positive control: the default (permitted) caller CAN subscribe and get a real event
    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    first_event = next(iter(resp["EventStream"]))
    assert "SubscribeToShardEvent" in first_event, (
        f"expected a SubscribeToShardEvent from the permitted caller, got {first_event!r}"
    )


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE")


def _wait_consumer_active(ctx, consumer_arn: str, timeout_s: float = 60.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"][
            "ConsumerStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"consumer {consumer_arn} never became ACTIVE")


def _error(fn):
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"subscribe_to_shard unexpectedly succeeded for an unauthorized user: {result!r}")


def _wait_for_expected_denial(client, consumer_arn, shard_id, expected_code, timeout_s=45.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        code, message = _error(
            lambda: client.subscribe_to_shard(
                ConsumerARN=consumer_arn,
                ShardId=shard_id,
                StartingPosition={"Type": "TRIM_HORIZON"},
            )
        )
        if code == expected_code:
            return code, message
        last_code = code
        # tolerate IAM access-key propagation lag (InvalidClientTokenId) shortly after creation
        time.sleep(3)
    raise AssertionError(f"expected {expected_code}, last observed {last_code!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
