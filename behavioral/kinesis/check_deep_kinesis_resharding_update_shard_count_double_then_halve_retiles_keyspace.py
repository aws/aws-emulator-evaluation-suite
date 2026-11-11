"""deep-kinesis-resharding-update-shard-count-double-then-halve-retiles-keyspace."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-kinesis-resharding-update-shard-count-double-then-halve-retiles-keyspace"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1
ROUTING_KEYS = 12


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


def _assert_open_tiling(shards, want_open, label):
    """The open shards partition [0, 2**128-1] exactly, and UNIFORM_SCALING made them equal."""
    open_ = sorted((s for s in shards if _is_open(s)), key=lambda s: _range(s)[0])
    ranges = [_range(s) for s in open_]
    assert len(open_) == want_open, f"{label}: {len(open_)} open shards, expected {want_open}: {ranges!r}"
    assert ranges[0][0] == 0 and ranges[-1][1] == MAX_HASH, (
        f"{label}: open shards do not span the keyspace: first {ranges[0]!r}, last {ranges[-1]!r}"
    )
    for (lo1, hi1), (lo2, hi2) in zip(ranges, ranges[1:]):
        assert hi1 + 1 == lo2, f"{label}: gap or overlap between {(lo1, hi1)!r} and {(lo2, hi2)!r}"
    sizes = [hi - lo + 1 for lo, hi in ranges]
    assert max(sizes) - min(sizes) <= 1, (
        f"{label}: UNIFORM_SCALING produced unequal open shards, sizes {sizes!r}"
    )
    return open_


def _assert_graph(shards, label):
    """Every derived shard names existing, CLOSED parents, and its range lies inside them;
    a merge child's range is exactly the union of its two (adjacent) parents."""
    by_id = {s["ShardId"]: s for s in shards}
    for s in shards:
        parents = [p for p in (s.get("ParentShardId"), s.get("AdjacentParentShardId")) if p]
        for p in parents:
            assert p in by_id, f"{label}: {s['ShardId']} names parent {p!r}, which ListShards omits"
            assert not _is_open(by_id[p]), (
                f"{label}: {s['ShardId']} names parent {p} which is still OPEN"
            )
        if len(parents) == 2:
            pr = sorted(_range(by_id[p]) for p in parents)
            assert pr[0][1] + 1 == pr[1][0], f"{label}: merge parents of {s['ShardId']} not adjacent: {pr!r}"
            assert _range(s) == (pr[0][0], pr[1][1]), (
                f"{label}: merge child {s['ShardId']} range {_range(s)!r} != union of parents {pr!r}"
            )
        elif len(parents) == 1:
            plo, phi = _range(by_id[parents[0]])
            lo, hi = _range(s)
            assert plo <= lo and hi <= phi, (
                f"{label}: split child {s['ShardId']} range {(lo, hi)!r} escapes parent {(plo, phi)!r}"
            )


def _assert_routing(c, name, open_, keys, label):
    """Each key is written to the open shard whose range holds MD5(key)."""
    open_ids = {s["ShardId"] for s in open_}
    for k in keys:
        deadline = time.monotonic() + 180
        while True:
            resp = c.put_record(StreamName=name, PartitionKey=k, Data=f"{label}|{k}".encode())
            if resp["ShardId"] in open_ids or time.monotonic() >= deadline:
                break
            time.sleep(1)   # routing lags a reshard; see _put_until_open
        owner = next(s["ShardId"] for s in open_ if _range(s)[0] <= _md5(k) <= _range(s)[1])
        assert resp["ShardId"] == owner, (
            f"{label}: PutRecord({k!r}) reported {resp['ShardId']}; MD5={_md5(k)} is owned by "
            f"open shard {owner}"
        )


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """UpdateShardCount 2->4 then 4->2 re-tiles the keyspace into equal open shards.

    Each step reports the counts, leaves exactly Target open shards with a consistent closed-parent
    lineage, and routes each key to the open shard owning MD5(key).
    """
    c = ctx.client("kinesis")
    name = _create_stream(ctx, c, 2)
    keys = [f"{name}-route-{i}" for i in range(ROUTING_KEYS)]
    original = _list_shards(c, name)
    _assert_open_tiling(original, 2, "initial")

    up = c.update_shard_count(StreamName=name, TargetShardCount=4, ScalingType="UNIFORM_SCALING")
    assert (up["StreamName"], up["CurrentShardCount"], up["TargetShardCount"]) == (name, 2, 4), (
        f"UpdateShardCount(4) echoed {up['StreamName']!r} "
        f"{up['CurrentShardCount']!r}->{up['TargetShardCount']!r}, expected {name!r} 2->4"
    )
    _await_topology(c, name, lambda sh: sum(1 for s in sh if _is_open(s)) == 4, "4 open shards in ListShards")
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["OpenShardCount"] == 4, f"OpenShardCount after doubling is {summary['OpenShardCount']!r}"
    doubled = _list_shards(c, name)
    open4 = _assert_open_tiling(doubled, 4, "after 2->4")
    _assert_graph(doubled, "after 2->4")
    orig_ids = {s["ShardId"] for s in original}
    assert all(s["ShardId"] not in orig_ids for s in open4), (
        f"an original shard is still open after doubling: {[s['ShardId'] for s in open4]!r}"
    )
    _assert_routing(c, name, open4, keys, "x4")

    down = c.update_shard_count(StreamName=name, TargetShardCount=2, ScalingType="UNIFORM_SCALING")
    assert (down["CurrentShardCount"], down["TargetShardCount"]) == (4, 2), (
        f"UpdateShardCount(2) echoed {down['CurrentShardCount']!r}->{down['TargetShardCount']!r}, "
        f"expected 4->2"
    )
    open4_ids_pre = {s["ShardId"] for s in open4}
    _await_topology(
        c, name,
        lambda sh: (sum(1 for s in sh if _is_open(s)) == 2
                    and all(not _is_open(s) for s in sh if s["ShardId"] in open4_ids_pre)),
        "2 new open shards in ListShards")
    summary = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary["OpenShardCount"] == 2, f"OpenShardCount after halving is {summary['OpenShardCount']!r}"
    halved = _list_shards(c, name)
    open2 = _assert_open_tiling(halved, 2, "after 4->2")
    _assert_graph(halved, "after 4->2")
    open4_ids = {s["ShardId"] for s in open4}
    for s in open2:
        assert s["ShardId"] not in open4_ids | orig_ids, (
            f"shard {s['ShardId']} is open after halving but existed before it"
        )
    assert all(not _is_open(s) for s in halved if s["ShardId"] in open4_ids), (
        "a shard that was open at 4 is still open after halving to 2"
    )
    _assert_routing(c, name, open2, keys, "x2")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
