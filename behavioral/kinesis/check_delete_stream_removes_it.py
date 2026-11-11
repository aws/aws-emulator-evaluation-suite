"""delete-stream-removes-it."""
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

def _error(fn):
    """Call fn(); return the (code, message, HTTP status) of the ClientError it raises. A
    success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

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

def _delete_stream_if_present(c, name):
    try:
        c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: _delete_stream_if_present(c, name))
    _wait_stream_ready(c, name)
    return name

def _wait_stream_deleted(c, name, timeout_s=150, interval_s=2):
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
    (shard id, sequence number, payload) in per-shard read order."""
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

CHECK = "delete-stream-removes-it"
GROUP = 'stream-lifecycle'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Records, binary ones included, read back byte-exact at their sequence numbers and in put
    order per shard; the deleted stream reads not-found, leaves ListStreams and refuses writes."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)

    payloads = [f"{name}-rec-{i}".encode() for i in range(5)]
    put = c.put_records(StreamName=name, Records=[
        {"Data": p, "PartitionKey": f"pk-{i}"} for i, p in enumerate(payloads)])
    assert put["FailedRecordCount"] == 0, f"PutRecords failed some records: {put!r}"
    assert len(put["Records"]) == 5 and all(r.get("SequenceNumber") for r in put["Records"]), (
        f"PutRecords did not return a SequenceNumber for every record: {put['Records']!r}"
    )
    written = {p: (r["ShardId"], r["SequenceNumber"]) for p, r in zip(payloads, put["Records"])}

    # Ordered writes: sequential PutRecord calls on one partition key, the first a binary
    # (non-UTF-8) payload, each chained to the previous with SequenceNumberForOrdering.
    ordered = [b"\xff\xfe\x00\x80" + name.encode()] + [f"{name}-ord-{i}".encode() for i in range(2)]
    prev = None
    for p in ordered:
        params = {"StreamName": name, "Data": p, "PartitionKey": "ordered"}
        if prev:
            params["SequenceNumberForOrdering"] = prev
        r = c.put_record(**params)
        prev = r["SequenceNumber"]
        written[p] = (r["ShardId"], r["SequenceNumber"])
    put_seqs = [int(written[p][1]) for p in ordered]
    assert put_seqs == sorted(put_seqs) and len(set(put_seqs)) == len(put_seqs), (
        f"sequential PutRecord calls returned non-ascending sequence numbers: {put_seqs!r}"
    )

    # Records become readable asynchronously: poll TRIM_HORIZON until every one is back.
    got = _poll(lambda: _read_all(c, name), lambda recs: set(written) <= {d for _, _, d in recs}, 60, 1.0,
                f"all {len(written)} records readable from {name}")
    datas = [d for _, _, d in got]
    for p, (shard_id, seq) in written.items():
        assert datas.count(p) == 1, f"record {p!r} read back {datas.count(p)} times, expected once (byte-exact)"
        read_shard, read_seq, _ = got[datas.index(p)]
        assert (read_shard, read_seq) == (shard_id, seq), (
            f"record {p!r} read back at {(read_shard, read_seq)!r}, written at {(shard_id, seq)!r}"
        )
    for shard_id in {sh for sh, _, _ in got}:
        seqs = [int(q) for sh, q, _ in got if sh == shard_id]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), (
            f"shard {shard_id} read back non-ascending sequence numbers: {seqs!r}"
        )
    ordered_read = [d for d in datas if d in ordered]
    assert ordered_read == ordered, f"ordered records read back out of put order: {ordered_read!r}"

    c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    _wait_stream_deleted(c, name)
    code, message, status = _error(lambda: c.describe_stream_summary(StreamName=name))
    assert code == "ResourceNotFoundException", f"expected the deleted stream to read back not-found, got {code!r}"
    assert message == f"Stream {params['StreamName']} under account {ctx.account} not found.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for the not-found read, got {status!r}"
    assert message, "the not-found read carried an empty message"

    _poll(lambda: _stream_names(c), lambda names: name not in names, 150, 2,
          f"deleted stream {name} leaving ListStreams")

    put_code, put_message, put_status = _error(lambda: c.put_record(StreamName=name, Data=b"post-delete", PartitionKey="k"))
    assert put_code == "ResourceNotFoundException", (
        f"expected PutRecord against the deleted stream to fail not-found, got {put_code!r}"
    )
    assert put_message == f"Stream {params['StreamName']} under account {ctx.account} not found.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {put_message!r}"
    )
    assert isinstance(put_status, int) and 400 <= put_status < 500, f"expected HTTP 4xx for PutRecord on the deleted stream, got {put_status!r}"
    assert put_message, "the PutRecord not-found refusal carried an empty message"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
