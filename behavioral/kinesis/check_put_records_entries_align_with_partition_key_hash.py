"""put-records-entries-align-with-partition-key-hash."""
from __future__ import annotations

import hashlib
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
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
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
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(
        c, name, ShardCount=shard_count, StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-kds"},
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


def _pk_hash(partition_key):
    """The explicit hash key Kinesis derives from a partition key: MD5 as a 128-bit int."""
    return int(hashlib.md5(partition_key.encode("utf-8")).hexdigest(), 16)


def _shard_for_key(shards, partition_key):
    h = _pk_hash(partition_key)
    for s in shards:
        lo = int(s["HashKeyRange"]["StartingHashKey"])
        hi = int(s["HashKeyRange"]["EndingHashKey"])
        if lo <= h <= hi:
            return s["ShardId"]
    raise AssertionError(
        f"partition key {partition_key!r} hashes to {h}, which falls in none of the shard "
        f"hash ranges {[(s['ShardId'], s['HashKeyRange']) for s in shards]}"
    )


CHECK = "put-records-entries-align-with-partition-key-hash"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecords Records[] is positionally aligned with the request (one success entry per record)
    and each ShardId is the shard whose HashKeyRange contains MD5(PartitionKey); each shard then
    yields exactly its subset.
    """
    c = ctx.client("kinesis")
    # pk-000/003/005 hash below 2**127 and pk-001/002/004 above, so keys interleave both shards.
    keys = ["pk-000", "pk-003", "pk-005", "pk-001", "pk-002", "pk-004"]
    entries = [{"Data": f"body-{k}".encode(), "PartitionKey": k} for k in keys]

    name = _provisioned_stream(ctx, c, shard_count=2)
    shards = _get_shards(c, name)
    assert len(shards) == 2, f"expected a 2-shard stream, ListShards gave {[s['ShardId'] for s in shards]}"

    expected = [_shard_for_key(shards, k) for k in keys]
    assert len(set(expected)) == 2, (
        f"fixture no longer discriminates: all of {keys} route to {set(expected)} under the "
        f"actual hash ranges {[(s['ShardId'], s['HashKeyRange']) for s in shards]}"
    )

    resp = _call_when_ready(lambda: c.put_records(StreamName=name, Records=entries))

    assert resp["FailedRecordCount"] == 0, (
        f"all {len(entries)} entries are well within the 500-record / 5 MB limits, but "
        f"FailedRecordCount={resp['FailedRecordCount']}; entries were {resp['Records']}"
    )
    results = resp["Records"]
    assert len(results) == len(entries), (
        f"PutRecords returned {len(results)} result entries for {len(entries)} request "
        f"entries; Records[] is positionally aligned with the request and must never be "
        f"compacted: {results}"
    )
    for i, r in enumerate(results):
        ok = "ShardId" in r and "SequenceNumber" in r
        bad = "ErrorCode" in r or "ErrorMessage" in r
        assert ok and not bad, (
            f"result entry {i} (key {keys[i]!r}) is {r}; a successful entry carries exactly "
            f"ShardId + SequenceNumber and no ErrorCode/ErrorMessage"
        )
        assert r["ShardId"] == expected[i], (
            f"result entry {i}: partition key {keys[i]!r} hashes to {_pk_hash(keys[i])}, "
            f"which lies in shard {expected[i]}'s HashKeyRange, but PutRecords reported "
            f"{r['ShardId']}"
        )

    # Read-back per shard: each shard holds exactly its own subset. PutRecords does not guarantee
    # record order, so the subset is compared order-insensitively.
    for shard in shards:
        sid = shard["ShardId"]
        want_bodies = [f"body-{k}".encode() for k, e in zip(keys, expected) if e == sid]
        assert want_bodies, f"shard {sid} was expected to receive at least one record"
        it = c.get_shard_iterator(
            StreamName=name, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        recs, _it, pages = _drain(c, it, want=len(want_bodies))
        got = [bytes(r["Data"]) for r in recs]
        assert got == want_bodies or sorted(got) == sorted(want_bodies), (
            f"shard {sid} yielded {got!r} over {pages} pages; expected exactly its hash-range "
            f"subset, {want_bodies!r}"
        )
        got_keys = [r["PartitionKey"] for r in recs]
        want_keys = [k for k, e in zip(keys, expected) if e == sid]
        assert got_keys == want_keys or sorted(got_keys) == sorted(want_keys), (
            f"shard {sid} returned partition keys {got_keys}, expected {want_keys}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
