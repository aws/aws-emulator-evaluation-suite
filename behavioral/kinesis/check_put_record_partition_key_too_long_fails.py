"""put-record-partition-key-too-long-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _shard_ids(c, name):
    return [s["ShardId"] for s in c.list_shards(StreamName=name)["Shards"]]

def _drain(c, iterator, want, timeout_s=120, interval_s=1.0, limit=1000):
    """Collect at least ``want`` records, chaining NextShardIterator across EMPTY pages."""
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, None, pages
        iterator = nxt
        if len(collected) >= want:
            return collected, iterator, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {pages} GetRecords pages over {timeout_s}s and saw "
                f"{len(collected)} of {want} expected records"
            )
        time.sleep(interval_s)

CHECK = "put-record-partition-key-too-long-fails"
GROUP = 'data-plane'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord accepts a 256-char PartitionKey but refuses 257 chars with ValidationException,
    storing nothing for the refused call; the boundary is pinned at +-1 char.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]
    at_limit_key = "k" * 256
    over_limit_key = "k" * 257

    # The at-limit control makes the refusal below attributable to PartitionKey length.
    put_ok = c.put_record(StreamName=name, Data=b"under", PartitionKey=at_limit_key)
    assert put_ok["ShardId"] == shard_id, (
        f"the at-limit-PartitionKey record landed on {put_ok['ShardId']}, not the only shard "
        f"{shard_id}"
    )

    try:
        c.put_record(StreamName=name, Data=b"over", PartitionKey=over_limit_key)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ValidationException", (
            f"PutRecord with a {len(over_limit_key)}-char PartitionKey failed with {code}; "
            f"real AWS answers ValidationException. The at-limit control of "
            f"{len(at_limit_key)} chars succeeded, so this is the length boundary and not a "
            f"broken stream"
        )
        expected_message = (
            f"1 validation error detected: Value '{over_limit_key}' at 'partitionKey' failed to "
            f"satisfy constraint: Member must have length less than or equal to 256"
        )
        assert message == expected_message, (
            f"PutRecord over-limit PartitionKey message {message!r}, expected {expected_message!r}"
        )
    else:
        raise AssertionError(
            f"PutRecord ACCEPTED a {len(over_limit_key)}-char PartitionKey; real AWS caps "
            f"PartitionKey at exactly 256 chars"
        )

    it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    recs, _next_it, pages = _drain(c, it, want=1)
    assert len(recs) == 1, (
        f"expected exactly the one accepted record on the shard after the refusal, found "
        f"{len(recs)} over {pages} pages"
    )
    assert bytes(recs[0]["Data"]) == b"under", (
        f"read back {bytes(recs[0]['Data'])!r}, expected the control payload b'under'"
    )

    tail = c.put_record(StreamName=name, Data=b"tail", PartitionKey=at_limit_key)
    assert int(tail["SequenceNumber"]) > int(put_ok["SequenceNumber"]), (
        f"post-refusal PutRecord returned sequence number {tail['SequenceNumber']}, which "
        f"does not advance past {put_ok['SequenceNumber']}"
    )
    it2 = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    final_recs, _next_it2, final_pages = _drain(c, it2, want=2)
    assert len(final_recs) == 2, (
        f"expected exactly 2 records on the shard (the at-limit control plus the post-refusal "
        f"tail), found {len(final_recs)} over {final_pages} pages"
    )
    assert bytes(final_recs[1]["Data"]) == b"tail", (
        f"the post-refusal record read back {bytes(final_recs[1]['Data'])!r}, expected b'tail'"
    )
    assert final_recs[1]["SequenceNumber"] == tail["SequenceNumber"], (
        f"the independently-read tail record's sequence number "
        f"{final_recs[1]['SequenceNumber']} does not match the one PutRecord returned "
        f"{tail['SequenceNumber']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
