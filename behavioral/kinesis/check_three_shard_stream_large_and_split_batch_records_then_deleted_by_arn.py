"""three-shard-stream-large-and-split-batch-records-then-deleted-by-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=40, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _error(fn):
    """Call fn(); return the (code, message, HTTP status) of the ClientError it raises. A
    success raises.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    deadline = time.monotonic() + 40
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
        if time.monotonic() >= deadline:
            break
        time.sleep(min(2 + attempt, 5))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=40, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=40):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 40, 2, f"stream {name} shards addressable")

def _delete_stream_if_present(c, name):
    try:
        c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_stream_if_present(c, name))
    _wait_stream_ready(c, name)
    return name

def _wait_stream_deleted(c, name, timeout_s=40, interval_s=2):
    def _gone():
        try:
            c.describe_stream_summary(StreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return True
            raise
        return False

    _poll(_gone, bool, timeout_s, interval_s, f"stream {name} deleted")

def _stream_names(c):
    names = []
    for page in c.get_paginator("list_streams").paginate():
        names.extend(page.get("StreamNames", []))
    return names

def _read_all(c, name):
    """Every record readable from TRIM_HORIZON across all shards (one pass), as
    (shard id, sequence number, payload) in per-shard read order.
    """
    out = []
    for shard in c.list_shards(StreamName=name)["Shards"]:
        it = c.get_shard_iterator(StreamName=name, ShardId=shard["ShardId"],
                                  ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        for _ in range(20):
            resp = c.get_records(ShardIterator=it, Limit=100)
            out.extend((shard["ShardId"], r["SequenceNumber"], r["Data"]) for r in resp["Records"])
            it = resp.get("NextShardIterator")
            if not it or not resp["Records"] and resp.get("MillisBehindLatest", 0) == 0:
                break
    return out

CHECK = "three-shard-stream-large-and-split-batch-records-then-deleted-by-arn"
GROUP = 'stream-lifecycle'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a three-shard stream, a large binary record and same-key records split across two PutRecords
    calls read back byte-exact and in put order; the stream deleted by ARN reads not-found by ARN and
    by name, leaves ListStreams and refuses writes and a second delete.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=3)
    arn = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    shards = c.list_shards(StreamName=name)["Shards"]
    assert len(shards) == 3, f"expected 3 shards, got {len(shards)}"

    # A deterministic 200 KiB payload covering every byte value.
    big = bytes((i * 31 + len(name)) % 256 for i in range(200 * 1024))
    batches = [
        [{"Data": big, "PartitionKey": "big"}] +
        [{"Data": f"{name}-a{i}".encode(), "PartitionKey": "same"} for i in range(3)],
        [{"Data": f"{name}-b{i}".encode(), "PartitionKey": "same"} for i in range(3)] +
        [{"Data": b"\x80\x81" + bytes([i]), "PartitionKey": f"spread-{i}"} for i in range(6)],
    ]
    written = {}
    for batch in batches:
        put = c.put_records(StreamARN=arn, Records=batch)
        assert put["FailedRecordCount"] == 0, f"PutRecords failed some records: {put!r}"
        for rec, r in zip(batch, put["Records"], strict=True):
            written[rec["Data"]] = (r["ShardId"], r["SequenceNumber"])
    same = [f"{name}-{x}{i}".encode() for x in "ab" for i in range(3)]
    assert len({written[p][0] for p in same}) == 1, "records of one partition key landed on several shards"

    got = _poll(lambda: _read_all(c, name), lambda recs: set(written) <= {d for _, _, d in recs}, 40, 1.0,
                f"all {len(written)} records readable from {name}")
    datas = [d for _, _, d in got]
    assert len(datas) == len(written), f"read back {len(datas)} records, wrote {len(written)}"
    for p, (shard_id, seq) in written.items():
        assert datas.count(p) == 1, f"a {len(p)}-byte record read back {datas.count(p)} times, expected once"
        read_shard, read_seq, _ = got[datas.index(p)]
        assert (read_shard, read_seq) == (shard_id, seq), (
            f"a {len(p)}-byte record read back at {(read_shard, read_seq)!r}, written at {(shard_id, seq)!r}"
        )
    assert [d for d in datas if d in same] == same, "same-key records read back out of put order"

    c.delete_stream(StreamARN=arn, EnforceConsumerDeletion=True)
    _wait_stream_deleted(c, name)
    missing = f"Stream {name} under account {ctx.account} not found."
    for label, call in (
        ("DescribeStreamSummary by ARN", lambda: c.describe_stream_summary(StreamARN=arn)),
        ("DescribeStreamSummary by name", lambda: c.describe_stream_summary(StreamName=name)),
        ("PutRecord by ARN", lambda: c.put_record(StreamARN=arn, Data=b"post-delete", PartitionKey="k")),
        ("PutRecords by name", lambda: c.put_records(StreamName=name, Records=[{"Data": b"x", "PartitionKey": "k"}])),
        ("a second DeleteStream", lambda: c.delete_stream(StreamARN=arn)),
    ):
        code, message, status = _error(call)
        assert (code, message) == ("ResourceNotFoundException", missing), (
            f"{label} on the deleted stream: got {code!r} {message!r}"
        )
        assert isinstance(status, int) and 400 <= status < 500, f"{label}: expected HTTP 4xx, got {status!r}"
    _poll(lambda: _stream_names(c), lambda names: name not in names, 40, 2,
          f"deleted stream {name} leaving ListStreams")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
