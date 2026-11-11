"""put-records-batch-success."""
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

def _drain(c, iterator, want, timeout_s=90, interval_s=1.0, limit=1000):
    collected = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if len(collected) >= want or nxt is None:
            return collected
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {len(collected)} of {want} expected records within {timeout_s}s: "
                f"{[bytes(r['Data']) for r in collected]!r}"
            )
        iterator = nxt
        time.sleep(interval_s)

CHECK = "put-records-batch-success"
GROUP = 'data-plane'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecords accepts a batch, reports zero failures, and the batch is independently readable back."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = c.list_shards(StreamName=name)["Shards"][0]["ShardId"]
    records = [{"Data": f"rec-{i}".encode(), "PartitionKey": f"pk-{i}"} for i in range(10)]
    resp = _call_when_ready(lambda: c.put_records(StreamName=name, Records=records))
    assert resp["FailedRecordCount"] == 0, (
        f"expected 0 failed records, got {resp['FailedRecordCount']}: {resp['Records']}"
    )
    assert len(resp["Records"]) == 10, (
        f"expected 10 per-record results from PutRecords, got {len(resp['Records'])}: {resp['Records']}"
    )

    iterator = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    got = _drain(c, iterator, want=10)
    assert len(got) == 10, (
        f"GetRecords returned {len(got)} records after draining the shard, expected the 10 just put: "
        f"{[bytes(r['Data']) for r in got]!r}"
    )
    got_payloads = sorted(bytes(r["Data"]) for r in got)
    want_payloads = sorted(r["Data"] for r in records)
    assert got_payloads == want_payloads, (
        f"GetRecords payloads {got_payloads!r} do not match the 10 payloads that were put {want_payloads!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
