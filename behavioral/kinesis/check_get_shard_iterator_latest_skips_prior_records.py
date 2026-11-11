"""get-shard-iterator-latest-skips-prior-records."""
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
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
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

def _call_when_ready(fn, timeout_s=90, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

CHECK = "get-shard-iterator-latest-skips-prior-records"
GROUP = 'data-plane'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A LATEST iterator obtained after a write returns no records, while a TRIM_HORIZON iterator
    on the same shard returns the earlier record (positive control against an always-empty read)."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]
    _call_when_ready(
        lambda: c.put_record(StreamName=name, Data=b"before-latest", PartitionKey="pk-1")
    )

    trim_it = c.get_shard_iterator(StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON")
    trim_records = _poll(
        lambda: c.get_records(ShardIterator=trim_it["ShardIterator"], Limit=10).get("Records", []),
        lambda recs: len(recs) >= 1,
        60, 2, f"stream {name} prior record visible via TRIM_HORIZON iterator",
    )
    assert len(trim_records) == 1, f"expected exactly 1 record via TRIM_HORIZON, got {len(trim_records)}"
    assert trim_records[0]["PartitionKey"] == "pk-1", (
        f"TRIM_HORIZON record partition key mismatch: expected 'pk-1', got {trim_records[0]['PartitionKey']!r}"
    )

    it_resp = c.get_shard_iterator(StreamName=name, ShardId=shard_id, ShardIteratorType="LATEST")
    resp = c.get_records(ShardIterator=it_resp["ShardIterator"], Limit=10)
    assert resp["Records"] == [], "LATEST iterator unexpectedly returned records written before it was issued"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
