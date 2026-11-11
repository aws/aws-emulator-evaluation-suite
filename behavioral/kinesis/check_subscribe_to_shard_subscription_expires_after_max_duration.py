"""subscribe-to-shard-subscription-expires-after-max-duration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "subscribe-to-shard-subscription-expires-after-max-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]


# timing:real-time — lease: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShard.html
@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """An enhanced-fan-out SubscribeToShard subscription is torn down by the service after its
    documented maximum duration window (up to 5 minutes), requiring the consumer to call
    SubscribeToShard again to keep receiving records."""
    # The documented subscription window is up to 5 minutes, so this check waits it out
    # (timing:real-time).
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    summary = _wait_stream_active(kinesis, name)
    stream_arn = summary["StreamARN"]
    shard_id = kinesis.list_shards(StreamName=name)["Shards"][0]["ShardId"]

    consumer_name = ctx.unique_name("sim2real-consumer-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _wait_consumer_active(kinesis, consumer_arn)

    resp = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn, ShardId=shard_id, StartingPosition={"Type": "LATEST"}
    )

    # "your consumer starts receiving events ... for up to 5 minutes, after which time you need
    # to call SubscribeToShard again to renew the subscription"
    # https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShard.html
    # Drain the event stream (this genuinely blocks for the duration of the window) and observe
    # that it terminates on its own, rather than asserting a fixed sleep duration.
    start = time.monotonic()
    closed_naturally = False
    try:
        for _event in resp["EventStream"]:
            if time.monotonic() - start > 420:
                break
        else:
            closed_naturally = True
    except Exception:
        # The service tearing down the HTTP/2 connection can surface as a stream-read error
        # rather than a clean StopIteration, depending on transport; either is "closed".
        closed_naturally = True
    elapsed = time.monotonic() - start

    assert closed_naturally, "subscription never terminated on its own within the safety window"
    assert 60 <= elapsed <= 400, f"subscription closed after an implausible duration: {elapsed}s"

    # Re-subscription is required to keep consuming, and it succeeds.
    resp2 = kinesis.subscribe_to_shard(
        ConsumerARN=consumer_arn, ShardId=shard_id, StartingPosition={"Type": "LATEST"}
    )
    assert "EventStream" in resp2


def _wait_stream_active(kinesis, name, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s (last={summary})")


def _wait_consumer_active(kinesis, consumer_arn, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)["ConsumerDescription"][
            "ConsumerStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"consumer {consumer_arn} did not become ACTIVE within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
