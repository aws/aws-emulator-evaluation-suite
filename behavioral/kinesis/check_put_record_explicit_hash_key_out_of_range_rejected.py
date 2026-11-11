"""put-record-explicit-hash-key-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-record-explicit-hash-key-out-of-range-rejected"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord with an ExplicitHashKey outside [0, 2**128-1] fails with InvalidArgumentException
    and its exact message; the shard holds only the two accepted in-range records, in order."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-")
    _create_and_wait_stream(ctx, stream_name, shard_count=1)
    shard_id = kinesis.list_shards(StreamName=stream_name)["Shards"][0]["ShardId"]

    # Positive control: an in-range ExplicitHashKey on this stream succeeds, so the
    # rejection below is attributable to the out-of-range value and not to a PutRecord
    # path that rejects everything.
    control = kinesis.put_record(
        StreamName=stream_name,
        Data=b"control-payload",
        PartitionKey="k",
        ExplicitHashKey="0",
    )
    assert control["ShardId"] == shard_id, (
        f"in-range ExplicitHashKey landed on {control['ShardId']!r}, not the only shard {shard_id!r}"
    )

    out_of_range_hash_key = str(2**128)  # valid domain is [0, 2**128 - 1]
    error = _client_error(
        lambda: kinesis.put_record(
            StreamName=stream_name,
            Data=b"out-of-range-payload",
            PartitionKey="k",
            ExplicitHashKey=out_of_range_hash_key,
        )
    )
    assert error.get("Code") == "InvalidArgumentException", (
        f"expected InvalidArgumentException for out-of-range ExplicitHashKey, got {error.get('Code')!r}"
    )
    expected_message = (
        "Invalid ExplicitHashKey. ExplicitHashKey must be in the range: [0, 2^128-1]. "
        f"Specified value was {out_of_range_hash_key}"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # The rejection did not wedge the stream: a further in-range write still succeeds.
    tail = kinesis.put_record(
        StreamName=stream_name,
        Data=b"tail-payload",
        PartitionKey="k",
        ExplicitHashKey="0",
    )
    assert int(tail["SequenceNumber"]) > int(control["SequenceNumber"]), (
        f"post-rejection PutRecord returned sequence number {tail['SequenceNumber']}, "
        f"which does not advance past {control['SequenceNumber']}"
    )

    # Terminal, independent read: the shard holds exactly the two accepted records, in
    # order, and never the rejected out-of-range one.
    records = _read_records(ctx, kinesis, stream_name, shard_id)
    payloads = [bytes(r["Data"]) for r in records]
    assert payloads == [b"control-payload", b"tail-payload"], (
        f"shard held {payloads!r}, expected exactly [control-payload, tail-payload] in "
        f"order; the out-of-range ExplicitHashKey record must not have landed anywhere"
    )


def _create_and_wait_stream(ctx, stream_name: str, shard_count: int = 1, timeout_s: float = 300.0) -> str:
    kinesis = ctx.client("kinesis")
    kinesis.create_stream(StreamName=stream_name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _client_error(fn):
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _read_records(ctx, kinesis, stream_name, shard_id, expect: int = 2, timeout_s: float = 60.0):
    """Drain the shard from TRIM_HORIZON to its current tip, retrying the whole drain
    until at least ``expect`` records are visible (GetRecords is only near-real-time)."""
    deadline = time.monotonic() + timeout_s
    collected: list = []
    while time.monotonic() < deadline:
        iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        collected = []
        while True:
            resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
            collected.extend(resp["Records"])
            next_it = resp.get("NextShardIterator")
            if next_it is None or not resp["Records"]:
                break
            iterator = next_it
        if len(collected) >= expect:
            return collected
        time.sleep(2)
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
