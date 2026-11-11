"""merged-shard-child-still-serves-parent-records."""
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
    # PROVISIONED with ShardCount=1 is the cheapest ACTIVE stream; ON_DEMAND has a strictly
    # higher floor cost, so it is only used where a check tests on-demand.
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
    """Collect >= ``want`` records and read to the tip of the shard (MillisBehindLatest == 0).

    An empty page alone is not terminal; reaching the tip is what makes absence meaningful.
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

    A null NextShardIterator, not an empty page, is a closed shard's only terminal signal.
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

    For a while after a reshard PutRecord still routes to a parent ListShards already reports
    CLOSED. Returns ``{shard_id: [payloads]}`` so the probes can be accounted for on read-back.
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


CHECK = "merged-shard-child-still-serves-parent-records"
GROUP = 'resharding'
SERVICES = ['kinesis']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """After MergeShards both parents still serve their own records and close out, and the
    child serves only records written after the merge, with no pre-merge record re-served.
    """
    c = ctx.client("kinesis")
    low_written = [f"pre-low-{i}".encode() for i in range(5)]
    high_written = [f"pre-high-{i}".encode() for i in range(5)]
    post_written = [f"post-merge-{i}".encode() for i in range(3)]

    name = _provisioned_stream(ctx, c, shard_count=2)
    shards = sorted(_get_shards(c, name), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]))
    assert len(shards) == 2, (
        f"expected a 2-shard stream, ListShards gave {[s['ShardId'] for s in shards]!r}"
    )
    low, high = shards[0], shards[1]

    for label, shard, payloads in (
        ("low", low, low_written), ("high", high, high_written),
    ):
        ehk = shard["HashKeyRange"]["StartingHashKey"]
        for i, payload in enumerate(payloads):
            resp = _call_when_ready(
                lambda p=payload, e=ehk, lb=label: c.put_record(
                    StreamName=name, Data=p, PartitionKey=f"pk-{lb}", ExplicitHashKey=e
                )
            )
            assert resp["ShardId"] == shard["ShardId"], (
                f"pre-merge record {i} ({payload!r}) with ExplicitHashKey={ehk!r} landed on "
                f"{resp['ShardId']!r}, not the intended {label} shard {shard['ShardId']!r}; the "
                f"merge below would then be testing the wrong lineage"
            )

    c.merge_shards(
        StreamName=name, ShardToMerge=low["ShardId"], AdjacentShardToMerge=high["ShardId"]
    )
    _wait_stream_ready(c, name)

    def _children():
        return [
            s for s in _get_shards(c, name)
            if s.get("ParentShardId") == low["ShardId"]
            and s.get("AdjacentParentShardId") == high["ShardId"]
        ]

    children = _poll(
        _children, lambda kids: len(kids) == 1, timeout_s=120, interval_s=3,
        description=f"one merged child of {low['ShardId']} + {high['ShardId']}",
    )
    child = children[0]

    after = {s["ShardId"]: s for s in _get_shards(c, name)}
    for label, shard in (("low", low), ("high", high)):
        assert "EndingSequenceNumber" in after[shard["ShardId"]]["SequenceNumberRange"], (
            f"the {label} parent {shard['ShardId']!r} is still open after the merge: "
            f"{after[shard['ShardId']]['SequenceNumberRange']!r}"
        )

    # The ingest path follows the merge only after the control plane reports it, so wait on
    # PutRecord's own reported ShardId. Probe records are real records in whichever shard took
    # them and are accounted for in every expectation below.
    probes = _put_until_routed_to(c, name, {child["ShardId"]}, "pk-probe")

    # Post-merge writes go to the open child, which now covers the whole key space.
    for i, payload in enumerate(post_written):
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="pk-post")
        )
        assert resp["ShardId"] == child["ShardId"], (
            f"post-merge record {i} ({payload!r}) landed on {resp['ShardId']!r}; the only open "
            f"shard is the merged child {child['ShardId']!r}, and PutRecord has already been "
            f"observed routing there by the probe {probes!r}"
        )

    low_expected = low_written + probes.get(low["ShardId"], [])
    high_expected = high_written + probes.get(high["ShardId"], [])
    child_expected = probes.get(child["ShardId"], []) + post_written

    def _iterator(shard_id):
        return c.get_shard_iterator(
            StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]

    low_after, low_pages = _drain_to_close(c, _iterator(low["ShardId"]))
    high_after, high_pages = _drain_to_close(c, _iterator(high["ShardId"]))
    child_recs, _child_it, child_pages = _drain_to_tip(
        c, _iterator(child["ShardId"]), want=len(child_expected)
    )

    assert [bytes(r["Data"]) for r in low_after] == low_expected, (
        f"the closed low parent {low['ShardId']!r} drained to "
        f"{[bytes(r['Data']) for r in low_after]!r} over {low_pages} pages; the "
        f"{len(low_written)} records written to it before the merge were {low_written!r} and must "
        f"still be readable through it, followed by any routing probe it took "
        f"({probes.get(low['ShardId'], [])!r})"
    )
    assert [bytes(r["Data"]) for r in high_after] == high_expected, (
        f"the closed high parent {high['ShardId']!r} drained to "
        f"{[bytes(r['Data']) for r in high_after]!r} over {high_pages} pages, expected "
        f"{high_expected!r}"
    )
    child_payloads = [bytes(r["Data"]) for r in child_recs]
    assert child_payloads == child_expected, (
        f"the merged child {child['ShardId']!r} read to its tip served {child_payloads!r} over "
        f"{child_pages} pages, expected exactly {child_expected!r} (the routing probe that "
        f"reached it, then the post-merge writes); the parents' records belong to the parents and "
        f"must not be re-served here"
    )
    overlap = (set(low_written) | set(high_written)) & set(child_payloads)
    assert not overlap, (
        f"the merged child re-served pre-merge records {sorted(overlap)!r}; a consumer that "
        f"drains parent-then-child, as the lineage requires, would process them twice"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
