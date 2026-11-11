"""deep-kinesis-resharding-per-key-order-survives-merge-via-lineage."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-kinesis-resharding-per-key-order-survives-merge-via-lineage"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1
KEYS_PER_PARENT = 3
PRE_MERGE = 4          # ordinals 0..3 per key are written before MergeShards
MIN_ON_CHILD = 3       # each key must also land >= 3 ordinals on the merged child


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
    """ACTIVE per DescribeStreamSummary AND listable: the summary flips to ACTIVE first."""
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

    DescribeStreamSummary can still read ACTIVE right after a reshard call returns, before the
    stream enters UPDATING, so readiness alone can return the pre-reshard shard map.
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

    Write routing moves off a resharded parent ~20 s after the stream is ACTIVE again, so this
    polls the reported ShardId and keeps every write for the read-back.
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


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Per-key order survives MergeShards: the key's parent read to its end, then the child, yields
    ordinals exactly 0..N-1; the other parent holds none of the key; each parent's terminal page
    names the child, which names both parents. Order across keys is not asserted.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_MergeShards.html
    """
    c = ctx.client("kinesis")
    name = _create_stream(ctx, c, 2)

    initial = sorted(_list_shards(c, name), key=lambda s: _range(s)[0])
    assert len(initial) == 2, f"a 2-shard stream listed {len(initial)} shards: {initial!r}"
    a, b = initial
    assert _range(a)[0] == 0 and _range(b)[1] == MAX_HASH and _range(a)[1] + 1 == _range(b)[0], (
        f"the two shards do not tile the keyspace: {_range(a)!r}, {_range(b)!r}"
    )
    a_id, b_id = a["ShardId"], b["ShardId"]
    split = _range(b)[0]

    def parent_of(key: str) -> str:
        return a_id if _md5(key) < split else b_id

    keys_a, keys_b = [], []
    for k in (f"{name}-ord-{i}" for i in range(100000)):
        bucket = keys_a if parent_of(k) == a_id else keys_b
        if len(bucket) < KEYS_PER_PARENT:
            bucket.append(k)
        if len(keys_a) == len(keys_b) == KEYS_PER_PARENT:
            break
    keys = keys_a + keys_b

    nxt = {k: 0 for k in keys}
    routed: dict[str, list[tuple[int, str]]] = {k: [] for k in keys}

    def put(k: str) -> str:
        o = nxt[k]
        resp = c.put_record(StreamName=name, PartitionKey=k, Data=f"{k}|{o}".encode())
        routed[k].append((o, resp["ShardId"]))
        nxt[k] = o + 1
        return resp["ShardId"]

    for _ in range(PRE_MERGE):
        for k in keys:
            shard = put(k)
            assert shard == parent_of(k), (
                f"pre-merge PutRecord({k!r}) reported {shard}, but MD5 places it in {parent_of(k)}"
            )

    c.merge_shards(StreamName=name, ShardToMerge=a_id, AdjacentShardToMerge=b_id)
    _await_topology(c, name, lambda sh: sum(1 for s in sh if _is_open(s)) == 1, "the merge visible in ListShards")

    shards = _list_shards(c, name)
    open_ = [s for s in shards if _is_open(s)]
    assert len(open_) == 1, f"after MergeShards {len(open_)} shards are open: {open_!r}"
    child = open_[0]
    child_id = child["ShardId"]
    assert {child.get("ParentShardId"), child.get("AdjacentParentShardId")} == {a_id, b_id}, (
        f"merged child {child_id} names parents ({child.get('ParentShardId')!r}, "
        f"{child.get('AdjacentParentShardId')!r}), expected {{{a_id!r}, {b_id!r}}}"
    )
    assert _range(child) == (0, MAX_HASH), f"merged child range {_range(child)!r} is not the keyspace"

    # Keep writing each key, one call at a time, until every key has MIN_ON_CHILD ordinals on
    # the child. Writes routed to a parent during the routing lag are legitimate and stay in
    # the graded log.
    deadline = time.monotonic() + 180
    while any(sum(1 for _o, s in routed[k] if s == child_id) < MIN_ON_CHILD for k in keys):
        assert time.monotonic() < deadline, (
            f"writes were still not reaching merged child {child_id} after 180s: "
            f"{ {k: [s for _o, s in routed[k][-3:]] for k in keys}!r}"
        )
        for k in keys:
            shard = put(k)
            assert shard in (parent_of(k), child_id), (
                f"post-merge PutRecord({k!r}) reported {shard}; only its own parent "
                f"{parent_of(k)} or the child {child_id} may own it"
            )
        time.sleep(0.5)

    # ---- the consumer: both parents to their end, then the child ------------------------ #
    logs, finals = {}, {}
    for pid in (a_id, b_id):
        recs, final = _drain_closed(c, name, pid)
        logs[pid], finals[pid] = recs, final
    want_child = sum(1 for k in keys for _o, s in routed[k] if s == child_id)
    logs[child_id] = _drain_open(c, name, child_id, want=want_child)

    def ordinals(shard_id: str, key: str) -> list[int]:
        return [int(r["Data"].decode().rsplit("|", 1)[1]) for r in logs[shard_id]
                if r["PartitionKey"] == key]

    for k in keys:
        mine, other = parent_of(k), (b_id if parent_of(k) == a_id else a_id)
        from_parent, from_child = ordinals(mine, k), ordinals(child_id, k)
        assert from_parent, f"no records for {k!r} were read from its parent {mine}"
        assert from_child, f"no records for {k!r} were read from the merged child {child_id}"
        assert from_parent + from_child == list(range(nxt[k])), (
            f"following {mine} then {child_id}, key {k!r} read ordinals "
            f"{from_parent!r} + {from_child!r}; expected exactly 0..{nxt[k] - 1} in order"
        )
        assert ordinals(other, k) == [], (
            f"parent {other} served {k!r}, whose MD5 is owned by {mine}: {ordinals(other, k)!r}"
        )

    for pid in (a_id, b_id):
        final = finals[pid]
        named = [cs["ShardId"] for cs in final.get("ChildShards", [])]
        assert named == [child_id], (
            f"parent {pid}'s terminal page named ChildShards {named!r}, expected [{child_id!r}]"
        )
        assert set(final["ChildShards"][0]["ParentShards"]) == {a_id, b_id}, (
            f"ChildShards on {pid} lists ParentShards {final['ChildShards'][0]['ParentShards']!r}, "
            f"expected both {a_id!r} and {b_id!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
