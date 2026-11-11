"""deep-kinesis-resharding-split-of-closed-parent-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-kinesis-resharding-split-of-closed-parent-rejected"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _md5(key: str) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16)


def _range(shard: dict) -> tuple[int, int]:
    return (int(shard["HashKeyRange"]["StartingHashKey"]),
            int(shard["HashKeyRange"]["EndingHashKey"]))


def _is_open(shard: dict) -> bool:
    return "EndingSequenceNumber" not in shard["SequenceNumberRange"]


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    """Delete the stream at teardown and prove it is gone.

    DeleteStream is refused with ResourceInUseException while the stream is UPDATING, so a bare
    ``on_cleanup(delete_stream)`` fails exactly when a check has just resharded.
    """

    def _teardown():
        deadline = time.monotonic() + timeout_s
        last = None
        deleted = False
        while time.monotonic() < deadline:
            try:
                c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
                deleted = True
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ResourceInUseException", "LimitExceededException"):
                    raise
                last = code
                time.sleep(interval_s)
        if not deleted:
            raise AssertionError(
                f"stream {name} never reached a deletable state within {timeout_s}s "
                f"(last error {last}); it is still billing shard-hours"
            )
        while time.monotonic() < deadline:
            try:
                c.describe_stream_summary(StreamName=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(interval_s)
        raise AssertionError(f"stream {name} still describable {timeout_s}s after DeleteStream")

    ctx.on_cleanup(_teardown)


def _await_ready(c, name, timeout_s=240):
    """ACTIVE per DescribeStreamSummary AND listable: the summary flips first (measured)."""
    def probe():
        s = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if s["StreamStatus"] != "ACTIVE":
            return s["StreamStatus"]
        try:
            c.list_shards(StreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
                return "ACTIVE-but-unlistable"
            raise
        return "READY"
    _poll(probe, lambda st: st == "READY", timeout_s, 2, f"stream {name} ACTIVE and listable")


def _await_topology(c, name, pred, description, timeout_s=240):
    """Poll until the stream is ready AND its shard map satisfies ``pred``; return the map.

    DescribeStreamSummary can still read ACTIVE immediately after
    SplitShard / MergeShards / UpdateShardCount returns, BEFORE the stream enters UPDATING, so
    readiness alone races the reshard and hands back the pre-reshard shard map.
    """
    def probe():
        _await_ready(c, name, timeout_s)
        return _list_shards(c, name)
    return _poll(probe, pred, timeout_s, 2, description)


def _create_stream(ctx, c, shard_count):
    name = ctx.unique_name("sim2real-behav-kre-")
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, ShardCount=shard_count,
                            StreamModeDetails={"StreamMode": "PROVISIONED"},
                            Tags={"sim2real": "deep-kinesis-resharding"})
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            time.sleep(min(5 + attempt * 2, 15))
    else:
        raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}")
    _register_stream_teardown(ctx, c, name)
    _await_ready(c, name)
    return name


def _list_shards(c, name):
    out, token = [], None
    while True:
        resp = c.list_shards(**({"NextToken": token} if token else {"StreamName": name}))
        out += resp["Shards"]
        token = resp.get("NextToken")
        if not token:
            return out


def _drain_closed(c, name, shard_id, max_pages=400):
    """Read a CLOSED shard to its end: the page with no NextShardIterator. Returns (records, final)."""
    it = c.get_shard_iterator(StreamName=name, ShardId=shard_id,
                              ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records = []
    for _ in range(max_pages):
        resp = c.get_records(ShardIterator=it, Limit=1000)
        records += resp["Records"]
        it = resp.get("NextShardIterator")
        if it is None:
            return records, resp
        time.sleep(0.25)
    raise AssertionError(f"closed shard {shard_id} never returned a null NextShardIterator "
                         f"in {max_pages} pages; read {len(records)} records")


def _drain_open(c, name, shard_id, want, timeout_s=120):
    """Read an OPEN shard until ``want`` records are in hand and a caught-up empty page follows."""
    it = c.get_shard_iterator(StreamName=name, ShardId=shard_id,
                              ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = c.get_records(ShardIterator=it, Limit=1000)
        records += resp["Records"]
        it = resp["NextShardIterator"]
        if (len(records) >= want and not resp["Records"]
                and resp.get("MillisBehindLatest", 1) == 0):
            return records
        time.sleep(0.5)
    raise AssertionError(f"open shard {shard_id} served {len(records)} of {want} expected "
                         f"records within {timeout_s}s")


def _put_until_open(c, name, key, closed_ids, tag, writes, timeout_s=180):
    """PutRecord ``key`` until the service routes it to an OPEN shard; log every write.

    On AWS, write routing moves off a split parent ~20 s AFTER the stream is back
    to ACTIVE, and records written in that window land in the (closed) parent. That window is AWS
    behaviour, so this polls the observable condition — the reported ShardId — rather than
    sleeping, and every write it makes is kept so the read-back can account for all of them.
    """
    deadline = time.monotonic() + timeout_s
    n = 0
    while True:
        data = f"{tag}-{n}"
        resp = c.put_record(StreamName=name, PartitionKey=key, Data=data.encode())
        writes.append((key, data, resp["ShardId"]))
        if resp["ShardId"] not in closed_ids:
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(f"PutRecord({key!r}) was still routed to closed shard "
                                 f"{resp['ShardId']} {timeout_s}s after the reshard landed")
        n += 1
        time.sleep(1)


def _refusal(fn):
    """Exact error code and message of a call that MUST be refused. A success is a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {resp!r}")


def _snapshot(c, name):
    return sorted((s["ShardId"], _range(s), _is_open(s), s.get("ParentShardId"),
                   s.get("AdjacentParentShardId")) for s in _list_shards(c, name))


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Splitting a shard that a previous split already CLOSED is InvalidArgumentException.

    The shard graph, OpenShardCount and the closed parent's records stay untouched ("... has already
    been merged or split"), and splitting one of its open children then succeeds.
    """
    c = ctx.client("kinesis")
    name = _create_stream(ctx, c, 1)
    parent = _list_shards(c, name)[0]["ShardId"]
    c.put_record(StreamName=name, PartitionKey=f"{name}-k", Data=b"parent-record")

    c.split_shard(StreamName=name, ShardToSplit=parent, NewStartingHashKey=str(2 ** 127))
    _await_topology(c, name, lambda sh: sum(1 for s in sh if s.get("ParentShardId") == parent) == 2,
                    f"the split of {parent} visible in ListShards")
    before = _snapshot(c, name)
    kids = sorted((row for row in before if row[3] == parent), key=lambda row: row[1][0])
    assert len(kids) == 2 and all(row[2] for row in kids), f"setup: split did not yield 2 open children: {before!r}"
    assert any(row[0] == parent and not row[2] for row in before), f"setup: parent {parent} is not closed: {before!r}"

    code, message = _refusal(lambda: c.split_shard(
        StreamName=name, ShardToSplit=parent, NewStartingHashKey=str(2 ** 126)))
    assert code == "InvalidArgumentException", (
        f"SplitShard on CLOSED parent {parent} returned {code!r}, expected InvalidArgumentException"
    )
    expected = (
        f"Shard {parent} in stream {name} under account {ctx.account} has already been merged "
        f"or split, and thus is not eligible for merging or splitting."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ---- effect absent -------------------------------------------------------------------- #
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["StreamStatus"] == "ACTIVE", f"stream is {summary['StreamStatus']!r} after the refusal"
    assert summary["OpenShardCount"] == 2, f"OpenShardCount is {summary['OpenShardCount']!r} after the refusal"
    assert _snapshot(c, name) == before, (
        f"the shard graph changed after a refused split: before {before!r}, after {_snapshot(c, name)!r}"
    )
    recs, final = _drain_closed(c, name, parent)
    assert [r["Data"] for r in recs] == [b"parent-record"], (
        f"closed parent now serves {[r['Data'] for r in recs]!r}, expected its one record"
    )
    assert sorted(cs["ShardId"] for cs in final.get("ChildShards", [])) == sorted(r[0] for r in kids), (
        f"the parent's terminal page names {final.get('ChildShards')!r}, expected {[r[0] for r in kids]!r}"
    )

    # ---- positive control: an OPEN child is splittable ------------------------------------ #
    low_id, (lo, hi) = kids[0][0], kids[0][1]
    c.split_shard(StreamName=name, ShardToSplit=low_id, NewStartingHashKey=str((lo + hi + 1) // 2))
    _await_topology(c, name, lambda sh: sum(1 for s in sh if s.get("ParentShardId") == low_id) == 2,
                    f"the split of {low_id} visible in ListShards")
    after = _snapshot(c, name)
    grandkids = [row for row in after if row[3] == low_id]
    assert len(grandkids) == 2 and all(row[2] for row in grandkids), (
        f"splitting open child {low_id} did not yield two open grandchildren: {after!r}"
    )
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["OpenShardCount"] == 3, (
        f"after the allowed split OpenShardCount is {summary['OpenShardCount']!r}, expected 3"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
