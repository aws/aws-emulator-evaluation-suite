"""split-shard-children-partition-parent-hash-range-and-records."""
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

    DeleteStream is refused with ResourceInUseException while the stream is CREATING or UPDATING.
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


def _wait_stream_active(c, name, timeout_s=180, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=180):
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
    # PROVISIONED with ShardCount=1 is the cheapest ACTIVE stream.
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(
        c, name, ShardCount=shard_count, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    _register_stream_teardown(ctx, c, name)
    _wait_stream_ready(c, name)
    return name


def _get_shards(c, name):
    shards = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {"StreamName": name}
        resp = c.list_shards(**kwargs)
        shards.extend(resp["Shards"])
        token = resp.get("NextToken")
        if not token:
            return shards


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
    """Collect at least ``want`` records, chaining NextShardIterator across EMPTY pages.

    GetRecords legitimately returns an empty page before a just-written record is visible, so
    an empty page is a retry — not a terminal condition.
    """
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


def _drain_to_tip(c, iterator, want, timeout_s=180, interval_s=1.0, limit=1000):
    """Collect >= ``want`` records and read until MillisBehindLatest == 0.

    Returns ``(records, next_iterator, pages)``; ``next_iterator`` is None once the shard is closed.
    """
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        at_tip = resp.get("MillisBehindLatest") == 0
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, None, pages
        iterator = nxt
        if len(collected) >= want and at_tip:
            return collected, iterator, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {pages} GetRecords pages over {timeout_s}s and saw "
                f"{len(collected)} of {want} expected records, MillisBehindLatest="
                f"{resp.get('MillisBehindLatest')!r}: "
                f"{[bytes(r['Data']) for r in collected]!r}"
            )
        time.sleep(interval_s)


def _drain_to_close(c, iterator, timeout_s=180, interval_s=1.0, limit=1000):
    """Drain a closed shard until GetRecords stops returning a NextShardIterator.

    A null NextShardIterator, not an empty page, is a closed shard's terminal signal.
    """
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, pages
        iterator = nxt
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"a closed shard was drained for {pages} pages over {timeout_s}s and GetRecords "
                f"still returns a NextShardIterator; it must go null once the parent is "
                f"exhausted. Records seen: {[bytes(r['Data']) for r in collected]!r}"
            )
        time.sleep(interval_s)


def _put_until_routed_to(c, name, expected_shard_ids, partition_key,
                        explicit_hash_key=None, timeout_s=180, interval_s=3):
    """Write probe records until PutRecord itself reports one of ``expected_shard_ids``.

    After a reshard PutRecord can still place records on a parent ListShards reports closed.
    Returns ``{shard_id: [payloads]}`` so probes are accounted for when shards are read back.
    """
    probes = {}
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        payload = f"routing-probe-{attempt}".encode()
        kwargs = {"StreamName": name, "Data": payload, "PartitionKey": partition_key}
        if explicit_hash_key is not None:
            kwargs["ExplicitHashKey"] = explicit_hash_key
        resp = _call_when_ready(lambda k=dict(kwargs): c.put_record(**k))
        probes.setdefault(resp["ShardId"], []).append(payload)
        if resp["ShardId"] in expected_shard_ids:
            return probes
        attempt += 1
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{timeout_s}s after the reshard closed the parent shard(s), PutRecord still "
                f"routes to {resp['ShardId']!r} instead of one of {sorted(expected_shard_ids)!r}; "
                f"probes written so far: {probes!r}"
            )
        time.sleep(interval_s)


CHECK = "split-shard-children-partition-parent-hash-range-and-records"
GROUP = 'resharding'
SERVICES = ['kinesis']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """A split's children tile the parent's hash range with no gap or overlap, the split point is
    inclusive in the high child, and records keyed either side of it are served by the right child.
    """
    c = ctx.client("kinesis")
    low_payload = b"below-split-point"
    high_payload = b"at-split-point"

    name = _provisioned_stream(ctx, c, shard_count=1)
    parents = _get_shards(c, name)
    assert len(parents) == 1, (
        f"expected a 1-shard stream, ListShards gave {[s['ShardId'] for s in parents]!r}"
    )
    parent = parents[0]
    parent_range = parent["HashKeyRange"]
    lo = int(parent_range["StartingHashKey"])
    hi = int(parent_range["EndingHashKey"])
    split_at = lo + (hi - lo) // 2 + 1
    assert lo < split_at <= hi, (
        f"setup invalid: split point {split_at} is not strictly inside the parent range "
        f"{parent_range!r}"
    )

    c.split_shard(
        StreamName=name, ShardToSplit=parent["ShardId"], NewStartingHashKey=str(split_at)
    )
    _wait_stream_ready(c, name)

    def _children():
        return sorted(
            (s for s in _get_shards(c, name) if s.get("ParentShardId") == parent["ShardId"]),
            key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]),
        )

    children = _poll(
        _children, lambda kids: len(kids) == 2, timeout_s=120, interval_s=3,
        description=f"two children of {parent['ShardId']} after the split",
    )
    child_low, child_high = children

    assert int(child_low["HashKeyRange"]["StartingHashKey"]) == lo, (
        f"the low child {child_low['ShardId']!r} starts at "
        f"{child_low['HashKeyRange']['StartingHashKey']!r}, but the parent started at "
        f"{parent_range['StartingHashKey']!r}; the children must cover the parent's whole range"
    )
    assert int(child_high["HashKeyRange"]["EndingHashKey"]) == hi, (
        f"the high child {child_high['ShardId']!r} ends at "
        f"{child_high['HashKeyRange']['EndingHashKey']!r}, but the parent ended at "
        f"{parent_range['EndingHashKey']!r}"
    )
    assert int(child_high["HashKeyRange"]["StartingHashKey"]) == split_at, (
        f"SplitShard was asked for NewStartingHashKey={split_at}, but the high child "
        f"{child_high['ShardId']!r} starts at {child_high['HashKeyRange']['StartingHashKey']!r}"
    )
    assert int(child_low["HashKeyRange"]["EndingHashKey"]) + 1 == int(
        child_high["HashKeyRange"]["StartingHashKey"]
    ), (
        f"the children leave a gap or an overlap in the parent's key space: the low child "
        f"{child_low['ShardId']!r} ends at {child_low['HashKeyRange']['EndingHashKey']!r} and the "
        f"high child {child_high['ShardId']!r} starts at "
        f"{child_high['HashKeyRange']['StartingHashKey']!r}; adjacent ranges differ by exactly 1"
    )

    parent_after = next(s for s in _get_shards(c, name) if s["ShardId"] == parent["ShardId"])
    assert "EndingSequenceNumber" in parent_after["SequenceNumberRange"], (
        f"the split parent {parent['ShardId']!r} is still open: "
        f"{parent_after['SequenceNumberRange']!r}"
    )

    # The ingest path follows the split only after the control plane reports it. Probe with the
    # same explicit hash key the low write will use, so the wait ends exactly when that key starts
    # resolving to the low child. Probes that landed on the parent stay in the parent, which is
    # never read below; the one that reached the low child is accounted for there.
    probes = _put_until_routed_to(
        c, name, {child_low["ShardId"]}, "pk-probe", str(split_at - 1)
    )

    # Routing consequence: one explicit hash key immediately below the split point and one exactly
    # at it. These are the two values an off-by-one in the range arithmetic sends to the wrong
    # child.
    routed = {}
    for label, payload, ehk in (
        ("low", low_payload, str(split_at - 1)), ("high", high_payload, str(split_at)),
    ):
        resp = _call_when_ready(
            lambda p=payload, e=ehk, lb=label: c.put_record(
                StreamName=name, Data=p, PartitionKey=f"pk-{lb}", ExplicitHashKey=e
            )
        )
        routed[label] = resp["ShardId"]

    assert routed["low"] == child_low["ShardId"], (
        f"a record with ExplicitHashKey={split_at - 1} (one below the split point) was placed on "
        f"{routed['low']!r}; the low child {child_low['ShardId']!r} owns "
        f"{child_low['HashKeyRange']!r}, and the probe {probes!r} already observed PutRecord "
        f"routing that key there"
    )
    assert routed["high"] == child_high["ShardId"], (
        f"a record with ExplicitHashKey={split_at} (exactly the split point) was placed on "
        f"{routed['high']!r}; NewStartingHashKey is INCLUSIVE in the high child "
        f"{child_high['ShardId']!r} with range {child_high['HashKeyRange']!r}"
    )

    low_expected = probes.get(child_low["ShardId"], []) + [low_payload]
    high_expected = probes.get(child_high["ShardId"], []) + [high_payload]

    def _payloads_on(shard_id, want):
        it = c.get_shard_iterator(
            StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        recs, _next_it, _pages = _drain_to_tip(c, it, want=want)
        return [bytes(r["Data"]) for r in recs]

    low_payloads = _payloads_on(child_low["ShardId"], len(low_expected))
    high_payloads = _payloads_on(child_high["ShardId"], len(high_expected))
    assert low_payloads == low_expected, (
        f"the low child {child_low['ShardId']!r} read to its tip served {low_payloads!r}, "
        f"expected exactly {low_expected!r}"
    )
    assert high_payloads == high_expected, (
        f"the high child {child_high['ShardId']!r} read to its tip served {high_payloads!r}, "
        f"expected exactly {high_expected!r}"
    )
    assert low_payload not in high_payloads, (
        f"the record keyed one below the split point is readable from the HIGH child "
        f"{child_high['ShardId']!r}: {high_payloads!r}. A hash key belongs to exactly one child"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
