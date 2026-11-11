"""put-record-oversized-data-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-oversized-data-rejected"
GROUP = "representation"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord with Data exceeding the 1 MiB per-record limit is rejected and the record
    never lands on the shard; a normal-sized record still succeeds afterward."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(
        StreamName=stream_name,
        ShardCount=1,
        Tags={"sim2real-check": "put-record-oversized-data-rejected"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(ctx, kinesis, stream_name)
    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]

    baseline = _read_records_once(ctx, kinesis, stream_name, shard_id)
    assert baseline == [], "freshly created stream unexpectedly already has records"

    oversized = b"x" * (1024 * 1024 + 1)  # 1 MiB + 1 byte, over the PutRecord Data limit
    error = _client_error(
        lambda: kinesis.put_record(StreamName=stream_name, Data=oversized, PartitionKey="oversized")
    )
    code = error.get("Code")
    # Real AWS enforces this above PutRecord's own modeled error surface (a front-end request
    # validator), so the code is ValidationException, never the modeled InvalidArgumentException.
    assert code == "ValidationException", f"expected ValidationException for a 1 MiB+1 Data blob, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'data' failed to satisfy constraint: "
        "Member must have length less than or equal to 1048576"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    after_reject = _read_records_once(ctx, kinesis, stream_name, shard_id)
    assert after_reject == [], "oversized record was rejected but data still landed on the shard"

    # positive control: a normal write on the same stream must still succeed
    kinesis.put_record(StreamName=stream_name, Data=b"normal-sized-payload", PartitionKey="control")
    landed = _wait_for_records(ctx, kinesis, stream_name, shard_id, expected=1)
    assert len(landed) == 1, f"expected exactly 1 record after the control write, got {len(landed)}"
    assert landed[0]["Data"] == b"normal-sized-payload", (
        f"read back {landed[0]['Data']!r}, expected the control payload b'normal-sized-payload'"
    )


def _wait_stream_active(ctx, kinesis, stream_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE" and _shards_addressable(kinesis, stream_name):
            return
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _shards_addressable(kinesis, stream_name):
    """ListShards can still see CREATING for a moment after the summary reports ACTIVE."""
    try:
        kinesis.list_shards(StreamName=stream_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceInUseException":
            return False
        raise
    return True


def _client_error(fn):
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _read_records_once(ctx, kinesis, stream_name, shard_id):
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    return kinesis.get_records(ShardIterator=iterator, Limit=100)["Records"]


def _wait_for_records(ctx, kinesis, stream_name, shard_id, expected, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        records = _read_records_once(ctx, kinesis, stream_name, shard_id)
        if len(records) >= expected:
            return records
        time.sleep(2)
    raise AssertionError(f"expected {expected} record(s), never observed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
