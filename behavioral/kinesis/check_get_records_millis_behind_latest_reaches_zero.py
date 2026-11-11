"""get-records-millis-behind-latest-reaches-zero."""
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

CHECK = "get-records-millis-behind-latest-reaches-zero"
GROUP = 'data-plane'
SERVICES = ['kinesis']

RECORD_COUNT = 5
PUT_GAP_S = 2.0

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """MillisBehindLatest is positive when reading the oldest of records written seconds apart,
    and exactly zero once the reader has caught up to the tip."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]

    for i in range(RECORD_COUNT):
        _call_when_ready(
            lambda i=i: c.put_record(StreamName=name, Data=f"record-{i}".encode(), PartitionKey="pk-1")
        )
        if i < RECORD_COUNT - 1:
            time.sleep(PUT_GAP_S)

    it_resp = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )

    first = _poll(
        lambda: c.get_records(ShardIterator=it_resp["ShardIterator"], Limit=1),
        lambda r: len(r.get("Records", [])) >= 1,
        timeout_s=60,
        interval_s=2,
        description="oldest record readable via TRIM_HORIZON iterator",
    )
    assert len(first["Records"]) == 1, first["Records"]
    assert first["MillisBehindLatest"] > 0, (
        f"expected positive lag with {RECORD_COUNT - 1} newer records ({(RECORD_COUNT - 1) * PUT_GAP_S}s "
        f"apart) still unread, got MillisBehindLatest={first['MillisBehindLatest']}"
    )

    remaining = RECORD_COUNT - 1
    next_iterator = first["NextShardIterator"]
    resp = _poll(
        lambda: c.get_records(ShardIterator=next_iterator, Limit=100),
        lambda r: len(r.get("Records", [])) >= remaining,
        timeout_s=60,
        interval_s=2,
        description="remaining records readable via TRIM_HORIZON iterator",
    )
    assert len(resp["Records"]) == remaining, resp["Records"]
    assert resp["MillisBehindLatest"] == 0, resp["MillisBehindLatest"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
