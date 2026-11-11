"""concurrent-writers-to-one-shard-lose-no-records."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

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

    GetRecords can return an empty page before a just-written record is visible.
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
    """Collect >= ``want`` records and read until MillisBehindLatest == 0 (the shard's tip).

    Returns ``(records, next_iterator, pages)``; ``next_iterator`` is None once the shard closes.
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


CHECK = "concurrent-writers-to-one-shard-lose-no-records"
GROUP = 'concurrency'
SERVICES = ['kinesis']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """Eight concurrent producers on one shard lose nothing, and each keeps its own key order.

    The multiset read back equals the multiset written and sequence numbers increase along the
    shard; the interleaving across partition keys is unspecified, so no global order is asserted.
    """
    c = ctx.client("kinesis")
    writers = 8
    per_writer = 10

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    written = [
        f"w{w}-{i:02d}".encode() for w in range(writers) for i in range(per_writer)
    ]
    barrier = threading.Barrier(writers)
    throttles = []
    lock = threading.Lock()

    def _write(w):
        key = f"pk-writer-{w}"
        seqs = []
        barrier.wait()
        for i in range(per_writer):
            payload = f"w{w}-{i:02d}".encode()
            # A throttled PutRecord was not stored, so retrying cannot create a duplicate.
            for attempt in range(6):
                try:
                    resp = c.put_record(StreamName=name, Data=payload, PartitionKey=key)
                    seqs.append(resp["SequenceNumber"])
                    break
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    if code not in (
                        "ProvisionedThroughputExceededException", "LimitExceededException",
                    ):
                        raise
                    with lock:
                        throttles.append((w, i, code))
                    time.sleep(0.5 * (attempt + 1))
            else:
                raise AssertionError(
                    f"writer {w} record {i} ({payload!r}) was throttled on all 6 attempts; a "
                    f"single shard ingests 1000 records/s and this test writes "
                    f"{writers * per_writer}"
                )
        return w, seqs

    with ThreadPoolExecutor(max_workers=writers) as pool:
        results = dict(pool.map(_write, range(writers)))

    for w, seqs in results.items():
        assert len(seqs) == per_writer, (
            f"writer {w} recorded {len(seqs)} sequence numbers for {per_writer} records: {seqs!r}"
        )

    it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records, _next_it, pages = _drain_to_tip(c, it, want=len(written), timeout_s=240)
    drained = [bytes(r["Data"]) for r in records]

    assert sorted(drained) == sorted(written), (
        f"{len(drained)} records were read back from {len(written)} concurrent writes over "
        f"{pages} pages; missing {sorted(set(written) - set(drained))!r} and unexpected "
        f"{sorted(set(drained) - set(written))!r}. Throttle retries: {throttles!r}"
    )
    assert len(drained) == len(written), (
        f"{len(drained)!r} records recovered, expected {len(written)!r}: a multiset match with a "
        f"length mismatch means a payload was served more than once. Pages: {pages}"
    )

    # The guarantee that DOES survive concurrency: per-partition-key order. Each writer used its
    # own key, so its own records must appear in the shard in the order that writer wrote them.
    for w in range(writers):
        prefix = f"w{w}-".encode()
        mine = [p for p in drained if p.startswith(prefix)]
        expected = [f"w{w}-{i:02d}".encode() for i in range(per_writer)]
        assert mine == expected, (
            f"writer {w} wrote {expected!r} under one partition key, but the shard serves them "
            f"as {mine!r}; Kinesis preserves order per partition key within a shard even when "
            f"other producers interleave"
        )

    # The sequence numbers the whole shard assigned are strictly increasing along the shard,
    # which is the ordering property that holds ACROSS keys — unlike the interleaving itself.
    as_ints = [int(r["SequenceNumber"]) for r in records]
    assert all(a < b for a, b in zip(as_ints, as_ints[1:])), (
        f"the shard served records with non-monotonic sequence numbers: "
        f"{[r['SequenceNumber'] for r in records]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
