"""explicit-hash-key-routes-record-to-chosen-shard."""
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

    DeleteStream is refused with ResourceInUseException while the stream is CREATING or
    UPDATING, so a bare ``on_cleanup(delete_stream)`` fails exactly when a check has just
    resharded — leaving a stream that bills shard-hours forever.
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


def _drain_to_tip(c, iterator, want, timeout_s=180, interval_s=1.0, limit=1000):
    """Collect >= ``want`` records AND read to the TIP of the shard.

    MillisBehindLatest == 0 is the observable condition meaning "this response is level with the
    end of the shard, there is nothing further to read". It is what makes an assertion about
    records that must be ABSENT from a shard meaningful: an empty page on its own is not
    terminal, because GetRecords legitimately returns one before a just-written record becomes
    visible. Returns ``(records, next_iterator, pages)``; ``next_iterator`` is None once the
    shard is closed, which is a distinct terminal signal from "level with the tip".
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


CHECK = "explicit-hash-key-routes-record-to-chosen-shard"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """ExplicitHashKey overrides the partition key's MD5 hash and picks the shard.

    With the same PartitionKey, the explicit key routes one record to the high shard and the
    default hash routes another to the low shard; reading both shards to the tip confirms each."""
    c = ctx.client("kinesis")
    routed_payload = b"ehk-routed-to-high"
    natural_payload = b"pk-routed-naturally"

    name = _provisioned_stream(ctx, c, shard_count=2)
    shards = sorted(_get_shards(c, name), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"]))
    assert len(shards) == 2, (
        f"expected a 2-shard stream, ListShards gave {[s['ShardId'] for s in shards]!r}"
    )
    low, high = shards[0], shards[1]

    # Pick a partition key whose OWN hash lands in the low shard, so the explicit key sends the
    # record somewhere its partition key never would.
    candidates = [f"pk-{i:03d}" for i in range(200)]
    pk = next((k for k in candidates if _shard_for_key(shards, k) == low["ShardId"]), None)
    assert pk is not None, (
        f"no candidate partition key of {candidates[0]!r}..{candidates[-1]!r} hashes into the "
        f"low shard {low['ShardId']!r} with range {low['HashKeyRange']!r}; the fixture cannot "
        f"discriminate"
    )
    explicit_hash_key = high["HashKeyRange"]["StartingHashKey"]

    # Setup validity, asserted rather than assumed: the explicit key is inside the HIGH shard and
    # the partition key's own hash is inside the LOW one. If these do not hold the check proves
    # nothing, so they fail loudly as setup errors.
    assert int(low["HashKeyRange"]["StartingHashKey"]) <= _pk_hash(pk) <= int(
        low["HashKeyRange"]["EndingHashKey"]
    ), (
        f"setup invalid: partition key {pk!r} hashes to {_pk_hash(pk)}, outside the low shard "
        f"range {low['HashKeyRange']!r}"
    )
    assert int(high["HashKeyRange"]["StartingHashKey"]) <= int(explicit_hash_key) <= int(
        high["HashKeyRange"]["EndingHashKey"]
    ), (
        f"setup invalid: ExplicitHashKey {explicit_hash_key!r} is outside the high shard range "
        f"{high['HashKeyRange']!r}"
    )

    routed = _call_when_ready(
        lambda: c.put_record(
            StreamName=name, Data=routed_payload, PartitionKey=pk,
            ExplicitHashKey=explicit_hash_key,
        )
    )
    assert routed["ShardId"] == high["ShardId"], (
        f"PutRecord with ExplicitHashKey={explicit_hash_key!r} (inside {high['ShardId']!r}'s "
        f"range {high['HashKeyRange']!r}) reported ShardId {routed['ShardId']!r}; the partition "
        f"key {pk!r} hashes to {_pk_hash(pk)}, so an implementation that ignored ExplicitHashKey "
        f"would answer {low['ShardId']!r} — which is exactly what it answered"
    )

    natural = _call_when_ready(
        lambda: c.put_record(StreamName=name, Data=natural_payload, PartitionKey=pk)
    )
    assert natural["ShardId"] == low["ShardId"], (
        f"the same partition key {pk!r} WITHOUT ExplicitHashKey reported ShardId "
        f"{natural['ShardId']!r}; MD5({pk!r}) is {_pk_hash(pk)}, which lies in "
        f"{low['ShardId']!r}'s range {low['HashKeyRange']!r}"
    )

    def _payloads_on(shard_id, want):
        it = c.get_shard_iterator(
            StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        recs, _next_it, _pages = _drain_to_tip(c, it, want=want)
        return [bytes(r["Data"]) for r in recs]

    high_payloads = _payloads_on(high["ShardId"], want=1)
    low_payloads = _payloads_on(low["ShardId"], want=1)

    assert high_payloads == [routed_payload], (
        f"the high shard {high['ShardId']!r} read to its tip returned {high_payloads!r}, "
        f"expected exactly the explicitly-routed record {[routed_payload]!r}"
    )
    assert low_payloads == [natural_payload], (
        f"the low shard {low['ShardId']!r} read to its tip returned {low_payloads!r}, expected "
        f"exactly the naturally-routed record {[natural_payload]!r}"
    )
    assert routed_payload not in low_payloads, (
        f"the record routed to {high['ShardId']!r} by ExplicitHashKey is ALSO readable from "
        f"{low['ShardId']!r}: {low_payloads!r}. A record lives in exactly one shard"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
