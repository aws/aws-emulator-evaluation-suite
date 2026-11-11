"""put-record-oversized-payload-rejected-before-limit-increase."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-oversized-payload-rejected-before-limit-increase"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord over the default 1 MiB max record size fails with ValidationException and is
    not ingested, while a normally-sized record on the same stream still succeeds."""
    kinesis = ctx.client("kinesis")
    name, stream_arn = _create_active_stream(ctx)

    oversized_payload = b"y" * (1024 * 1024 + 200 * 1024)  # ~1.2 MiB, over the untouched default limit

    error = _client_error(
        lambda: kinesis.put_record(StreamARN=stream_arn, Data=oversized_payload, PartitionKey="pk")
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')}"
    expected_message = (
        "1 validation error detected: Value at 'data' failed to satisfy constraint: "
        "Member must have length less than or equal to 1048576"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records_after_rejection = kinesis.get_records(StreamARN=stream_arn, ShardIterator=iterator)["Records"]
    assert records_after_rejection == [], "the rejected oversized record should never have been ingested"

    # Positive control, same stream: a normally-sized record still goes through.
    small_payload = b"ok"
    put_resp = kinesis.put_record(StreamARN=stream_arn, Data=small_payload, PartitionKey="pk")
    assert put_resp["SequenceNumber"], f"expected a SequenceNumber in the PutRecord response, got {put_resp!r}"

    iterator2 = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records_after_control = _read_records(kinesis, iterator2, 1, StreamARN=stream_arn)
    assert len(records_after_control) == 1, f"expected exactly 1 record, got {len(records_after_control)}"
    assert records_after_control[0]["Data"] == small_payload, (
        f"expected {small_payload!r}, got {records_after_control[0]['Data']!r}"
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


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _read_records(kinesis, iterator, count, timeout_s=60.0, interval_s=1.0, **kwargs):
    """Records read along NextShardIterator until at least count arrive or timeout_s passes:
    GetRecords may return an empty page while data is still pending."""
    records = []
    deadline = time.monotonic() + timeout_s
    while iterator and time.monotonic() < deadline:
        page = kinesis.get_records(ShardIterator=iterator, **kwargs)
        records.extend(page["Records"])
        iterator = page.get("NextShardIterator")
        if len(records) >= count:
            return records
        time.sleep(interval_s)
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
