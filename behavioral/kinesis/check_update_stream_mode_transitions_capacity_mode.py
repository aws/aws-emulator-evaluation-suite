"""update-stream-mode-transitions-capacity-mode."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-mode-transitions-capacity-mode"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateStreamMode toggles PROVISIONED -> ON_DEMAND and the new mode is
    visible via DescribeStreamSummary once the stream settles back to ACTIVE."""
    kinesis = ctx.client("kinesis")
    stream = _create_provisioned_stream(ctx)

    before = kinesis.describe_stream_summary(StreamName=stream["name"])["StreamDescriptionSummary"]
    assert before["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"expected PROVISIONED before UpdateStreamMode, got {before['StreamModeDetails']}"
    )

    kinesis.update_stream_mode(
        StreamARN=stream["arn"], StreamModeDetails={"StreamMode": "ON_DEMAND"}
    )

    after = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream["name"])["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=180,
        interval_s=3,
    )
    assert after["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected ON_DEMAND after UpdateStreamMode, got {after['StreamModeDetails']}"
    )

    # The data plane must keep functioning across the capacity-mode switch: prove the
    # written record is actually retrievable through an independent read (GetShardIterator +
    # GetRecords), not merely that PutRecord returned without raising.
    payload = b"on-demand-payload"
    put = kinesis.put_record(StreamName=stream["name"], Data=payload, PartitionKey="pk-1")
    shard_id, sequence_number = put["ShardId"], put["SequenceNumber"]

    iterator = kinesis.get_shard_iterator(
        StreamName=stream["name"],
        ShardId=shard_id,
        ShardIteratorType="AT_SEQUENCE_NUMBER",
        StartingSequenceNumber=sequence_number,
    )["ShardIterator"]
    record = _drain_for_record(kinesis, iterator, timeout_s=30, interval_s=2)
    assert record["Data"] == payload, (
        f"expected GetRecords to return {payload!r} for sequence {sequence_number}, "
        f"got {record['Data']!r}"
    )
    assert record["PartitionKey"] == "pk-1", (
        f"expected PartitionKey 'pk-1', got {record['PartitionKey']!r}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _drain_for_record(kinesis, iterator, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=10)
        if resp["Records"]:
            return resp["Records"][0]
        iterator = resp["NextShardIterator"]
        time.sleep(interval_s)
    raise AssertionError(f"GetRecords returned no records within {timeout_s}s")


def _create_provisioned_stream(ctx, shard_count=1):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kmode-")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)

    def _cleanup():
        try:
            kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
