"""hot-key-skew-across-split-shard-with-in-flight-traffic."""
from __future__ import annotations

import collections
import hashlib
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "hot-key-skew-across-split-shard-with-in-flight-traffic"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1
MIN_PRE_SPLIT = 150        # hot records produced before SplitShard is called
MIN_POST_CUTOVER = 120     # hot records that must land on the child after the cutover
MAX_HOT = 2200             # hard cap: one shard sustains 1000 rec/s, we pace far below it
MAX_PRODUCE_S = 170.0
COLD_KEYS = 65             # 5 background writers x 13 keys each
MIN_COLD = 100             # background records written across the topology change


def _md5_int(key: str) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16)


def _list_shards(kin, name: str) -> list[dict]:
    """Every shard, open and closed. Paginated: a resharded stream outgrows one page."""
    out: list[dict] = []
    token = None
    while True:
        resp = kin.list_shards(**({"NextToken": token} if token else {"StreamName": name}))
        out += resp["Shards"]
        token = resp.get("NextToken")
        if not token:
            return out


def _await_active(kin, name: str) -> None:
    """Poll until the stream is ACTIVE *and* ListShards agrees.

    ListShards can still raise ResourceInUseException after DescribeStreamSummary reports ACTIVE.
    """
    deadline = time.monotonic() + 300
    status = ""
    while time.monotonic() < deadline:
        status = kin.describe_stream_summary(
            StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            try:
                kin.list_shards(StreamName=name)
                return
            except kin.exceptions.ResourceInUseException:
                pass
        time.sleep(2)
    raise AssertionError(
        f"stream {name!r} never became ACTIVE and listable; last status {status!r}"
    )


def _range(shard: dict) -> tuple[int, int]:
    return (int(shard["HashKeyRange"]["StartingHashKey"]),
            int(shard["HashKeyRange"]["EndingHashKey"]))


def _drain(ctx, kin, name: str, shard_id: str, closed: bool) -> tuple[list[dict], dict]:
    """Drain one shard to its end. Returns (records, the final GetRecords response).

    A closed shard returns caught-up empty pages with a live iterator before it ends, so it is
    drained to the absent iterator (the page carrying ``ChildShards``); an open one to caught-up.
    """
    iterator = kin.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records: list[dict] = []
    last: dict = {}
    deadline = time.monotonic() + 100
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while time.monotonic() < deadline:
        resp = kin.get_records(ShardIterator=iterator, Limit=1000)
        last = resp
        records += resp["Records"]
        iterator = resp.get("NextShardIterator")
        if iterator is None:
            return records, last
        if not closed and not resp["Records"] and resp.get("MillisBehindLatest", 1) == 0:
            return records, last
        time.sleep(0.25)
    raise AssertionError(
        f"shard {shard_id!r} (closed={closed}) did not drain within 100 s of GetRecords pages"
    )


def _hot_verdict(observations: list[tuple[int, str]], parent: str, child_low: str) -> tuple:
    """Order-independent verdict over the hot key's reported routing, keyed by each ordinal.

    Kinesis does not define the order concurrent PutRecord calls are observed in, only key ownership.
    """
    by_ordinal = dict(observations)
    ordinals = sorted(by_ordinal)
    seq = [by_ordinal[o] for o in ordinals]
    cutovers = [i for i in range(1, len(seq)) if seq[i] != seq[i - 1]]
    k = next((i for i, shard in enumerate(seq) if shard != parent), None)
    return (
        len(observations),
        len(by_ordinal),
        tuple(ordinals) == tuple(range(len(ordinals))),
        tuple(sorted(set(seq))),
        k,
        tuple(cutovers),
        None if k is None else (set(seq[:k]) == {parent} and set(seq[k:]) == {child_low}),
    )


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SplitShard with traffic in flight splits the hot key's log at one index: earlier ordinals in
    the parent, the rest in the MD5-selected child, no gap, duplicate or migration; cold keys intact.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SplitShard.html
    """
    kin = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-d5-")

    kin.create_stream(StreamName=name, ShardCount=2,
                      StreamModeDetails={"StreamMode": "PROVISIONED"},
                      Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: _delete_stream(kin, name))
    _await_active(kin, name)

    initial = sorted(_list_shards(kin, name), key=lambda s: _range(s)[0])
    assert len(initial) == 2, f"a 2-shard stream reported {len(initial)} shards: {initial!r}"
    assert _range(initial[0])[0] == 0, f"first shard does not start at 0: {_range(initial[0])!r}"
    assert _range(initial[-1])[1] == MAX_HASH, (
        f"last shard does not end at 2**128-1: {_range(initial[-1])!r}"
    )
    assert _range(initial[0])[1] + 1 == _range(initial[1])[0], (
        f"the two shards' hash ranges do not tile: {_range(initial[0])!r} then {_range(initial[1])!r}"
    )

    parent = initial[1]["ShardId"]
    p_lo, p_hi = _range(initial[1])
    hot_key = next(k for k in (f"hot-{name}-{i}" for i in range(100000))
                   if p_lo < _md5_int(k) < p_hi - 1)
    hot_hash = _md5_int(hot_key)
    split_at = hot_hash + 1          # so MD5(hot_key) falls in the LOW child, not the high one

    hot: list[tuple[int, str, str]] = []          # (ordinal, reported shard, sequence number)
    cold: list[tuple[str, str, str]] = []         # (partition key, data, reported shard)
    lock = threading.Lock()
    stop = threading.Event()

    def produce_hot() -> None:
        ordinal = 0
        while not stop.is_set() and ordinal < MAX_HOT:
            resp = kin.put_record(StreamName=name, PartitionKey=hot_key,
                                  Data=f"h{ordinal}".encode())
            with lock:
                hot.append((ordinal, resp["ShardId"], resp["SequenceNumber"]))
            ordinal += 1
            time.sleep(0.03)

    def produce_cold(tid: int) -> None:
        n = 0
        while not stop.is_set() and n < 200:
            key = f"cold-{name}-{tid}-{n % 13}"
            resp = kin.put_record(StreamName=name, PartitionKey=key,
                                  Data=f"c{tid}-{n}".encode())
            with lock:
                cold.append((key, f"c{tid}-{n}", resp["ShardId"]))
            n += 1
            time.sleep(0.5)

    split_issued = False
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(produce_hot)] + [pool.submit(produce_cold, t) for t in range(5)]
        deadline = time.monotonic() + MAX_PRODUCE_S
        try:
            while time.monotonic() < deadline:
                with lock:
                    produced = len(hot)
                    on_child = sum(1 for _o, shard, _s in hot if shard != parent)
                    n_cold = len(cold)
                if not split_issued and produced >= MIN_PRE_SPLIT:
                    kin.split_shard(StreamName=name, ShardToSplit=parent,
                                    NewStartingHashKey=str(split_at))
                    split_issued = True
                # Stop on counts, not on how fast the split lands, so the cold volume is fixed.
                if produced >= MAX_HOT or (on_child >= MIN_POST_CUTOVER and n_cold >= MIN_COLD):
                    break
                time.sleep(0.5)
        finally:
            stop.set()
        for future in futures:
            future.result()

    assert split_issued, f"the producer never reached {MIN_PRE_SPLIT} records, so no split was issued"
    n_hot = len(hot)
    routed = [(ordinal, shard) for ordinal, shard, _seq in hot]
    on_child = sum(1 for _o, shard in routed if shard != parent)
    assert on_child >= MIN_POST_CUTOVER, (
        f"only {on_child} of {n_hot} hot records were routed off the parent before the producer "
        f"stopped; the split did not land inside the production window"
    )

    _await_active(kin, name)
    after = _list_shards(kin, name)
    children = sorted((s for s in after if s.get("ParentShardId") == parent),
                      key=lambda s: _range(s)[0])
    assert len(children) == 2, (
        f"SplitShard produced {len(children)} children of {parent!r}: "
        f"{[(s['ShardId'], s.get('ParentShardId')) for s in after]!r}"
    )
    child_low, child_high = children[0]["ShardId"], children[1]["ShardId"]
    lo_lo, lo_hi = _range(children[0])
    hi_lo, hi_hi = _range(children[1])
    assert (lo_lo, hi_hi) == (p_lo, p_hi), (
        f"the children do not cover the parent's range {(p_lo, p_hi)!r}: got {(lo_lo, hi_hi)!r}"
    )
    assert lo_hi + 1 == hi_lo, f"the children's ranges do not tile: {lo_hi!r} then {hi_lo!r}"
    assert hi_lo == split_at, f"the low/high boundary is {hi_lo!r}, not the requested {split_at!r}"
    assert lo_lo <= hot_hash <= lo_hi, (
        f"MD5({hot_key!r}) = {hot_hash} is not in the low child's range {(lo_lo, lo_hi)!r}; "
        f"the hot key changed owner across the split"
    )

    # ---- routing: the hot key sees the parent, then its child, and nothing else ---------- #
    seen_shards = {shard for _o, shard in routed}
    assert seen_shards <= {parent, child_low}, (
        f"the hot key's records were routed to {sorted(seen_shards)!r}; only {parent!r} and "
        f"{child_low!r} own MD5({hot_key!r})"
    )
    verdict = _hot_verdict(routed, parent, child_low)
    n_obs, n_distinct, contiguous, shards_seen, k, cutovers, phased = verdict
    assert n_distinct == n_obs == n_hot and contiguous, (
        f"the producer's ordinals are not 0..{n_hot - 1} exactly: {n_obs} calls, {n_distinct} ordinals"
    )
    assert k is not None and 0 < k < n_hot, (
        f"the cutover index is {k!r} with N={n_hot}: the split landed outside the production "
        f"window, so nothing about the parent->child boundary was exercised"
    )
    assert cutovers == (k,), (
        f"the reported shard flapped: transitions at {cutovers!r}, expected exactly one at {k}"
    )
    assert phased, (
        f"ordinals 0..{k - 1} did not all report {parent!r} and {k}..{n_hot - 1} did not all "
        f"report {child_low!r}"
    )
    shuffled = random.sample(routed, len(routed))
    assert shuffled != routed, "shuffle produced the identical list; the invariance test would be vacuous"
    assert _hot_verdict(shuffled, parent, child_low) == verdict, (
        "the routing verdict is NOT shuffle-invariant, so this check depends on the order in "
        "which concurrent PutRecord calls were observed — which Kinesis does not define"
    )
    assert shards_seen in ((parent, child_low), (child_low, parent)), shards_seen

    # ---- the shards' actual contents ----------------------------------------------------- #
    drained: dict[str, list[dict]] = {}
    finals: dict[str, dict] = {}
    for shard_id in [initial[0]["ShardId"], parent, child_low, child_high]:
        drained[shard_id], finals[shard_id] = _drain(ctx, kin, name, shard_id,
                                                    closed=shard_id == parent)

    def hot_ordinals(shard_id: str) -> list[int]:
        return [int(r["Data"].decode()[1:]) for r in drained[shard_id]
                if r["PartitionKey"] == hot_key]

    parent_ords, low_ords = hot_ordinals(parent), hot_ordinals(child_low)
    assert parent_ords == list(range(k)), (
        f"the parent's hot-key log is not ordinals 0..{k - 1}: got {len(parent_ords)} records, "
        f"first/last {parent_ords[:3]!r}/{parent_ords[-3:]!r}"
    )
    assert low_ords == list(range(k, n_hot)), (
        f"the low child's hot-key log is not ordinals {k}..{n_hot - 1}: got {len(low_ords)} "
        f"records, first/last {low_ords[:3]!r}/{low_ords[-3:]!r}"
    )
    assert not set(parent_ords) & set(low_ords), (
        f"records are visible from BOTH the parent and its child: "
        f"{sorted(set(parent_ords) & set(low_ords))[:10]!r}"
    )
    assert hot_ordinals(child_high) == [], (
        f"the HIGH child served {len(hot_ordinals(child_high))} records for a key whose MD5 is "
        f"in the LOW child's range"
    )
    assert [r for r in drained[initial[0]['ShardId']] if r["PartitionKey"] == hot_key] == [], (
        "the untouched shard served records for the hot key"
    )

    # ---- the parent's terminal page names its children ----------------------------------- #
    final = finals[parent]
    assert "NextShardIterator" not in final, (
        f"the closed parent's last GetRecords page still carried a NextShardIterator: "
        f"{final.get('NextShardIterator')!r}"
    )
    named = sorted(cs["ShardId"] for cs in final.get("ChildShards", []))
    assert named == sorted([child_low, child_high]), (
        f"the parent's last page named ChildShards {named!r}, expected {sorted([child_low, child_high])!r}"
    )
    assert all(parent in cs["ParentShards"] for cs in final["ChildShards"]), (
        f"a ChildShards entry does not name {parent!r} as its parent: {final['ChildShards']!r}"
    )

    closed = next(s for s in after if s["ShardId"] == parent)
    end_seq = closed["SequenceNumberRange"].get("EndingSequenceNumber")
    assert end_seq is not None, f"the split parent is still open: {closed['SequenceNumberRange']!r}"
    low_seqs = [int(r["SequenceNumber"]) for r in drained[child_low]]
    assert int(end_seq) < min(low_seqs), (
        f"the parent's EndingSequenceNumber {end_seq} is not below the child's first sequence "
        f"number {min(low_seqs)} — the boundary is not a real sequence-number cut"
    )

    # Terminal state, not a hang: reading AT the parent's end yields nothing and no iterator.
    tail = kin.get_records(ShardIterator=kin.get_shard_iterator(
        StreamName=name, ShardId=parent, ShardIteratorType="AT_SEQUENCE_NUMBER",
        StartingSequenceNumber=end_seq)["ShardIterator"], Limit=10)
    assert tail["Records"] == [], f"reading AT the parent's end returned {len(tail['Records'])} records"
    assert "NextShardIterator" not in tail, (
        f"reading AT the parent's end handed back another iterator: {tail.get('NextShardIterator')!r}"
    )

    # ---- the cold keys: nothing lost, nothing misrouted, across the topology change ------ #
    ranges = {s["ShardId"]: _range(s) for s in after}
    assert len(cold) >= MIN_COLD, f"only {len(cold)} background records were written: {len(cold)}"
    assert len({key for key, _d, _s in cold}) == COLD_KEYS, (
        f"the background writers used {len({key for key, _d, _s in cold})} distinct keys, "
        f"expected {COLD_KEYS}"
    )
    for key, data, shard in cold:
        lo, hi = ranges[shard]
        assert lo <= _md5_int(key) <= hi, (
            f"PutRecord routed {key!r} (MD5 {_md5_int(key)}) to {shard!r} whose range is "
            f"{(lo, hi)!r} — {data!r}"
        )
    written = collections.Counter(data for _k, data, _s in cold)
    reported = {data: shard for _k, data, shard in cold}
    got = collections.Counter()
    for shard_id, records in drained.items():
        for record in records:
            if record["PartitionKey"] == hot_key:
                continue
            data = record["Data"].decode()
            got[data] += 1
            assert reported[data] == shard_id, (
                f"{data!r} was reported on {reported[data]!r} at write time but drained from "
                f"{shard_id!r} — a record migrated between shards"
            )
    assert got == written, (
        f"the background multiset changed across the split: wrote {sum(written.values())} "
        f"records, drained {sum(got.values())}; missing "
        f"{sorted((written - got).elements())[:10]!r}, extra {sorted((got - written).elements())[:10]!r}"
    )

    # ---- verified teardown: a leaked stream bills shard-hours ---- #
    kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    gone = False
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            kin.describe_stream_summary(StreamName=name)
        except kin.exceptions.ResourceNotFoundException:
            gone = True
            break
        time.sleep(3)
    assert gone, f"stream {name!r} was still describable 120 s after delete_stream"


def _delete_stream(kin, name):
    """Teardown for a run that stopped early; the run itself deletes the stream on success."""
    try:
        kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except kin.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
