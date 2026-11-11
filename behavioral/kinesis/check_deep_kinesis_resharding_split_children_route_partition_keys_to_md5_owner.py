"""deep-kinesis-resharding-split-children-route-partition-keys-to-md5-owner."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-kinesis-resharding-split-children-route-partition-keys-to-md5-owner"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1
KEYS_PER_CHILD = 20


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

    DeleteStream is refused with ResourceInUseException while the stream is UPDATING.
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
    """Wait until ACTIVE per DescribeStreamSummary AND listable: the summary flips first."""
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

    The summary can still read ACTIVE right after a reshard call, before the stream is UPDATING.
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

    Routing leaves a split parent ~20 s after the stream is ACTIVE; earlier writes land in the parent.
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a split, each partition key is written to, and only readable from, its MD5 owner.

    The owner is the child whose HashKeyRange contains MD5(key); an ExplicitHashKey in the other
    child's range moves the same key there.
    """
    c = ctx.client("kinesis")
    name = _create_stream(ctx, c, 1)

    initial = _list_shards(c, name)
    assert len(initial) == 1, f"a 1-shard stream listed {len(initial)} shards: {initial!r}"
    parent = initial[0]["ShardId"]
    assert _range(initial[0]) == (0, MAX_HASH), (
        f"the only shard does not own the whole keyspace: {_range(initial[0])!r}"
    )

    # Deliberately not the midpoint, so an even split or round-robin routing misplaces keys.
    split_at = MAX_HASH // 3 + 0x5EED
    c.split_shard(StreamName=name, ShardToSplit=parent, NewStartingHashKey=str(split_at))
    _await_topology(c, name, lambda sh: sum(1 for s in sh if s.get("ParentShardId") == parent) == 2,
                    f"the split of {parent} visible in ListShards")

    shards = _list_shards(c, name)
    by_id = {s["ShardId"]: s for s in shards}
    assert not _is_open(by_id[parent]), (
        f"the split parent {parent} is still open: {by_id[parent]['SequenceNumberRange']!r}"
    )
    children = sorted((s for s in shards if s.get("ParentShardId") == parent),
                      key=lambda s: _range(s)[0])
    assert len(children) == 2, (
        f"SplitShard produced {len(children)} children of {parent}: "
        f"{[(s['ShardId'], s.get('ParentShardId')) for s in shards]!r}"
    )
    low, high = children
    assert _range(low) == (0, split_at - 1), (
        f"low child range {_range(low)!r}, expected (0, {split_at - 1}) for split point {split_at}"
    )
    assert _range(high) == (split_at, MAX_HASH), (
        f"high child range {_range(high)!r}, expected ({split_at}, 2**128-1)"
    )
    owner_of = {low["ShardId"]: _range(low), high["ShardId"]: _range(high)}

    def owner(key: str) -> str:
        h = _md5(key)
        return low["ShardId"] if h < split_at else high["ShardId"]

    candidates = (f"{name}-pk-{i}" for i in range(100000))
    low_keys, high_keys = [], []
    for k in candidates:
        bucket = low_keys if _md5(k) < split_at else high_keys
        if len(bucket) < KEYS_PER_CHILD:
            bucket.append(k)
        if len(low_keys) == len(high_keys) == KEYS_PER_CHILD:
            break

    # Settle: both probes must be routed to an open shard before the routing claim is graded.
    writes: list[tuple[str, str, str]] = []
    _put_until_open(c, name, low_keys[0], {parent}, "settle-lo", writes)
    _put_until_open(c, name, high_keys[0], {parent}, "settle-hi", writes)

    graded: list[tuple[str, str, str]] = []
    for lk, hk in zip(low_keys, high_keys):
        for k in (lk, hk):
            data = f"post-{k}"
            resp = c.put_record(StreamName=name, PartitionKey=k, Data=data.encode())
            writes.append((k, data, resp["ShardId"]))
            graded.append((k, data, resp["ShardId"]))

    for k, data, shard in graded:
        assert shard == owner(k), (
            f"PutRecord({k!r}) reported {shard}, but MD5(key)={_md5(k)} is owned by {owner(k)} "
            f"(low child range {_range(low)!r}, high {_range(high)!r})"
        )

    # Hash, not key history: the same key forced to the high child's first hash moves there.
    forced = c.put_record(StreamName=name, PartitionKey=low_keys[1], Data=b"forced-high",
                          ExplicitHashKey=str(split_at))
    writes.append((low_keys[1], "forced-high", forced["ShardId"]))
    assert forced["ShardId"] == high["ShardId"], (
        f"ExplicitHashKey={split_at} (the high child's StartingHashKey) routed to "
        f"{forced['ShardId']}, not {high['ShardId']}; routing must follow the hash, not the key"
    )

    # ---- read back: each record is where it was reported, and nowhere else ---------------- #
    reported: dict[str, set] = {}
    for _k, data, shard in writes:
        reported.setdefault(shard, set()).add(data)
    parent_recs, _final = _drain_closed(c, name, parent)
    got = {parent: [r["Data"].decode() for r in parent_recs]}
    for child in (low["ShardId"], high["ShardId"]):
        recs = _drain_open(c, name, child, want=len(reported.get(child, ())))
        got[child] = [r["Data"].decode() for r in recs]
        lo, hi = owner_of[child]
        for r in recs:
            if r["Data"] == b"forced-high":
                continue
            assert lo <= _md5(r["PartitionKey"]) <= hi, (
                f"{child} (range {(lo, hi)!r}) served {r['PartitionKey']!r} whose MD5 is "
                f"{_md5(r['PartitionKey'])} — outside its range"
            )

    for shard_id, datas in got.items():
        assert len(datas) == len(set(datas)), f"{shard_id} served duplicates: {sorted(datas)!r}"
        assert set(datas) == reported.get(shard_id, set()), (
            f"{shard_id} served {sorted(set(datas))!r} but PutRecord attributed "
            f"{sorted(reported.get(shard_id, set()))!r} to it"
        )

    post_low = {f"post-{k}" for k in low_keys}
    post_high = {f"post-{k}" for k in high_keys}
    assert post_low <= set(got[low["ShardId"]]), (
        f"low child is missing {sorted(post_low - set(got[low['ShardId']]))!r}"
    )
    assert post_high <= set(got[high["ShardId"]]), (
        f"high child is missing {sorted(post_high - set(got[high['ShardId']]))!r}"
    )
    assert not post_low & set(got[high["ShardId"]]), (
        f"the HIGH child served low-owned keys: {sorted(post_low & set(got[high['ShardId']]))!r}"
    )
    assert not post_high & set(got[low["ShardId"]]), (
        f"the LOW child served high-owned keys: {sorted(post_high & set(got[low['ShardId']]))!r}"
    )
    assert not (post_low | post_high) & set(got[parent]), (
        f"the CLOSED parent served post-settle records: "
        f"{sorted((post_low | post_high) & set(got[parent]))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
