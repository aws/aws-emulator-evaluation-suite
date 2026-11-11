"""closed-parent-shard-drains-to-null-next-iterator."""
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
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    """Delete the stream at teardown and prove it is gone.

    DeleteStream is refused with ResourceInUseException while the stream is UPDATING after a split.
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
        raise AssertionError(
            f"stream {name} is still describable {timeout_s}s after DeleteStream returned; leak"
        )

    ctx.on_cleanup(_teardown)


def _wait_stream_active(c, name, timeout_s=240, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=240):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "ResourceInUseException", "ResourceNotFoundException",
            ):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 120, 2, f"stream {name} shards addressable")


def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(
        c, name, ShardCount=shard_count, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    _register_stream_teardown(ctx, c, name)
    _wait_stream_ready(c, name)
    return name


def _get_shards(c, name):
    return c.list_shards(StreamName=name)["Shards"]


def _call_when_ready(fn, timeout_s=120, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "ResourceInUseException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _drain(c, iterator, want, timeout_s=180, interval_s=1.0, limit=1000):
    """Collect at least ``want`` records, chaining NextShardIterator across EMPTY pages."""
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, None, pages
        iterator = nxt
        if len(collected) >= want:
            return collected, iterator, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {pages} GetRecords pages over {timeout_s}s and saw "
                f"{len(collected)} of {want} expected records: "
                f"{[bytes(r['Data']) for r in collected]!r}"
            )
        time.sleep(interval_s)


def _drain_best_effort(c, iterator, rounds=5, interval_s=2.0, limit=1000):
    """Read several consecutive pages of a shard expected to be empty; bounded by page count."""
    collected = []
    for _ in range(rounds):
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            break
        iterator = nxt
        time.sleep(interval_s)
    return collected


def _drain_until_closed(c, iterator, timeout_s=180, interval_s=1.0, limit=1000):
    """Drain a CLOSED shard until GetRecords omits NextShardIterator.

    Returns ``(records, child_shards, pages)``.
    """
    collected = []
    children = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        if resp.get("ChildShards"):
            children = resp["ChildShards"]
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, children, pages
        iterator = nxt
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"a closed shard never returned a null NextShardIterator: drained {pages} "
                f"pages over {timeout_s}s, collecting "
                f"{[bytes(r['Data']) for r in collected]!r}. A consumer can never advance "
                f"to the child shards without this terminal signal"
            )
        time.sleep(interval_s)


CHECK = "closed-parent-shard-drains-to-null-next-iterator"
GROUP = 'resharding'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """After SplitShard the parent closes, drains in order, and ends with a null iterator.

    The children partition the parent's hash range exactly, writes eventually route to them, every
    record is readable from the shard PutRecord named, and the last parent page lists ChildShards.
    """
    c = ctx.client("kinesis")
    pre = [b"pre-0", b"pre-1", b"pre-2"]
    post = [b"post-0", b"post-1"]

    name = _provisioned_stream(ctx, c, shard_count=1)
    shards0 = _get_shards(c, name)
    assert len(shards0) == 1, f"expected a 1-shard stream, got {[s['ShardId'] for s in shards0]}"
    parent = shards0[0]
    parent_id = parent["ShardId"]
    lo = int(parent["HashKeyRange"]["StartingHashKey"])
    hi = int(parent["HashKeyRange"]["EndingHashKey"])
    mid = (lo + hi) // 2 + 1

    for payload in pre:
        _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="pre-key")
        )

    c.split_shard(
        StreamName=name, ShardToSplit=parent_id, NewStartingHashKey=str(mid)
    )
    _wait_stream_active(c, name)

    shards1 = _poll(
        lambda: _get_shards(c, name),
        lambda ss: len(ss) == 3,
        timeout_s=180, interval_s=3,
        description=f"stream {name} showing parent + 2 children",
    )
    by_id = {s["ShardId"]: s for s in shards1}
    closed_parent = by_id[parent_id]
    assert "EndingSequenceNumber" in closed_parent["SequenceNumberRange"], (
        f"parent {parent_id} has no EndingSequenceNumber after SplitShard; a split parent is "
        f"closed to new writes and must be marked so: {closed_parent['SequenceNumberRange']}"
    )

    children = sorted(
        (s for s in shards1 if s.get("ParentShardId") == parent_id),
        key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]),
    )
    assert len(children) == 2, (
        f"expected exactly 2 shards with ParentShardId={parent_id}, got "
        f"{[(s['ShardId'], s.get('ParentShardId')) for s in shards1]}"
    )
    for child in children:
        assert "AdjacentParentShardId" not in child, (
            f"child {child['ShardId']} carries AdjacentParentShardId="
            f"{child.get('AdjacentParentShardId')}; that field belongs to a MERGE result, "
            f"not a split result"
        )
        assert "EndingSequenceNumber" not in child["SequenceNumberRange"], (
            f"child {child['ShardId']} is already closed: {child['SequenceNumberRange']}"
        )

    c0, c1 = children
    c0_lo = int(c0["HashKeyRange"]["StartingHashKey"])
    c0_hi = int(c0["HashKeyRange"]["EndingHashKey"])
    c1_lo = int(c1["HashKeyRange"]["StartingHashKey"])
    c1_hi = int(c1["HashKeyRange"]["EndingHashKey"])
    assert (c0_lo, c0_hi, c1_lo, c1_hi) == (lo, mid - 1, mid, hi), (
        f"children must partition the parent's hash range [{lo}, {hi}] exactly at the "
        f"requested NewStartingHashKey {mid}: expected "
        f"[{lo}, {mid - 1}] and [{mid}, {hi}], got [{c0_lo}, {c0_hi}] and [{c1_lo}, {c1_hi}]"
    )

    # Write routing settles asynchronously: after the stream is ACTIVE with parent + 2 children,
    # PutRecord can keep routing to the closed parent for ~20 s. Those records are readable from
    # the parent, so the response ShardId is the authority on where each record landed.
    settle_deadline = time.monotonic() + 180
    produced = []  # (payload, reported ShardId) in production order
    attempt = 0
    while True:
        payload = f"settle-{attempt}".encode()
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="post-key")
        )
        produced.append((payload, resp["ShardId"]))
        assert resp["ShardId"] in (parent_id, c0["ShardId"], c1["ShardId"]), (
            f"PutRecord reported shard {resp['ShardId']!r}, which is neither the parent "
            f"{parent_id} nor a child {[c0['ShardId'], c1['ShardId']]}"
        )
        if resp["ShardId"] != parent_id:
            break
        assert time.monotonic() < settle_deadline, (
            f"PutRecord kept routing to the CLOSED parent {parent_id} for 180s after the "
            f"stream went ACTIVE with parent + 2 children; write routing must eventually move "
            f"to the children or every post-split producer writes into a closed shard forever "
            f"(reported shards so far: {[s for _p, s in produced]})"
        )
        attempt += 1
        time.sleep(3)

    # Once routing has settled, a closed parent accepts no further writes.
    post_shards = []
    for payload in post:
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="post-key")
        )
        post_shards.append(resp["ShardId"])
        produced.append((payload, resp["ShardId"]))
    assert all(sid != parent_id for sid in post_shards), (
        f"post-split PutRecord returned shard ids {post_shards}, which include the closed "
        f"parent {parent_id}; once routing has moved to a child (proved by the settle write "
        f"above) a closed shard accepts no writes"
    )
    assert set(post_shards) <= {c0["ShardId"], c1["ShardId"]}, (
        f"post-split records landed on {set(post_shards)}, which are not the children "
        f"{[c0['ShardId'], c1['ShardId']]}"
    )
    # Records written during the settle window and reported against the parent belong to the
    # parent's content; everything else belongs to the child it named.
    settle_on_parent = [p for p, s in produced if s == parent_id]

    parent_it = c.get_shard_iterator(
        StreamName=name, ShardId=parent_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    parent_recs, child_shards, parent_pages = _drain_until_closed(c, parent_it)
    parent_data = [bytes(r["Data"]) for r in parent_recs]
    assert parent_data == pre + settle_on_parent, (
        f"the closed parent {parent_id} yielded {parent_data!r} over {parent_pages} pages; it "
        f"must hold exactly the pre-split records followed by the settle-window records whose "
        f"PutRecord response named this shard, in order: {pre + settle_on_parent!r}. Every "
        f"record PutRecord attributed to the parent must be readable FROM the parent — an "
        f"emulator that reports a shard id it does not honour is caught here"
    )
    for payload in post:
        assert payload not in parent_data, (
            f"post-split record {payload!r} appeared on the closed parent {parent_id}: "
            f"{parent_data!r}"
        )
    assert child_shards, (
        f"the final GetRecords page on closed parent {parent_id} carried no ChildShards; a "
        f"consumer discovers the children from that field, so its absence strands the "
        f"consumer at the end of the parent"
    )
    named = sorted(cs["ShardId"] for cs in child_shards)
    assert named == sorted([c0["ShardId"], c1["ShardId"]]), (
        f"ChildShards named {named}, expected exactly the two children "
        f"{sorted([c0['ShardId'], c1['ShardId']])}"
    )
    for cs in child_shards:
        assert parent_id in cs.get("ParentShards", []), (
            f"ChildShards entry {cs['ShardId']} lists ParentShards="
            f"{cs.get('ParentShards')}, which does not include {parent_id}"
        )

    # The post-split records are readable from the child that took them, in order, and the
    # pre-split records are not replayed on either child.
    for child in children:
        sid = child["ShardId"]
        want_bodies = [p for p, s in produced if s == sid]
        it = c.get_shard_iterator(
            StreamName=name, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        if want_bodies:
            recs, _it, pages = _drain(c, it, want=len(want_bodies), timeout_s=120)
            got = [bytes(r["Data"]) for r in recs]
            assert got == want_bodies, (
                f"child {sid} yielded {got!r} over {pages} pages; expected exactly the "
                f"records whose PutRecord response named this shard, in order: {want_bodies!r}"
            )
        else:
            got = [bytes(r["Data"]) for r in _drain_best_effort(c, it)]
            assert got == [], (
                f"child {sid} was never named by a PutRecord response, so it must be empty, "
                f"but reading it from TRIM_HORIZON yielded {got!r}. Pre-split records belong "
                f"to the closed parent and must not be replayed on a child"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
