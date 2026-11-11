"""deleted-stream-name-recreates-an-empty-stream."""
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

CHECK = "deleted-stream-name-recreates-an-empty-stream"
GROUP = 'stream-lifecycle'
SERVICES = ['kinesis']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deleted stream's name is free again: a new stream under it starts empty with its own shards,
    TRIM_HORIZON reads only the new record byte-exact, and none of the deleted stream's records or
    sequence numbers come back; the second stream then deletes and reads not-found too.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=2)
    first_created = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamCreationTimestamp"]
    old = [f"{name}-old-{i}".encode() for i in range(4)]
    put = c.put_records(StreamName=name, Records=[{"Data": p, "PartitionKey": f"pk-{i}"} for i, p in enumerate(old)])
    assert put["FailedRecordCount"] == 0, f"PutRecords failed some records: {put!r}"
    old_seqs = {r["SequenceNumber"] for r in put["Records"]}
    _poll(lambda: _read_all(c, name), lambda recs: set(old) <= {d for _, _, d in recs}, 40, 1.0,
          "the first stream's records readable")

    c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    _wait_stream_deleted(c, name)
    code, message, _ = _error(lambda: c.describe_stream_summary(StreamName=name))
    assert (code, message) == ("ResourceNotFoundException", f"Stream {name} under account {ctx.account} not found."), (
        f"the deleted stream: got {code!r} {message!r}"
    )

    _create_stream_with_retry(c, name, ShardCount=1, Tags={"sim2real": CHECK})
    _wait_stream_ready(c, name)
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["OpenShardCount"] == 1, f"the re-created stream has {summary['OpenShardCount']} open shards"
    assert summary["StreamCreationTimestamp"] > first_created, "the re-created stream kept the old creation time"
    assert summary["StreamARN"].endswith(f":stream/{name}"), "the re-created stream ARN does not name the stream"

    fresh = b"\x00\xfe" + name.encode()
    r = c.put_record(StreamName=name, Data=fresh, PartitionKey="pk-0")
    got = _poll(lambda: _read_all(c, name), lambda recs: fresh in {d for _, _, d in recs}, 40, 1.0,
                "the re-created stream's record readable")
    assert [(s, q, d) for s, q, d in got] == [(r["ShardId"], r["SequenceNumber"], fresh)], (
        f"the re-created stream read back {got!r}, expected only its own record"
    )
    assert r["SequenceNumber"] not in old_seqs, "the re-created stream reused a deleted record's sequence number"

    c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    _wait_stream_deleted(c, name)
    code, message, status = _error(lambda: c.put_record(StreamName=name, Data=b"post-delete", PartitionKey="k"))
    assert (code, message) == ("ResourceNotFoundException", f"Stream {name} under account {ctx.account} not found."), (
        f"PutRecord on the deleted re-created stream: got {code!r} {message!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx, got {status!r}"
    _poll(lambda: _stream_names(c), lambda names: name not in names, 40, 2,
          f"deleted stream {name} leaving ListStreams")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
