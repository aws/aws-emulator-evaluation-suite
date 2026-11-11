"""at-sequence-number-from-foreign-shard-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

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
        Tags={"sim2real-check": CHECK},
    )
    _register_stream_teardown(ctx, c, name)
    _wait_stream_ready(c, name)
    return name


def _shard_ids(c, name):
    return [s["ShardId"] for s in c.list_shards(StreamName=name)["Shards"]]


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


def _drain_best_effort(c, iterator, timeout_s=20, limit=1000):
    """Drain whatever is immediately available; used only to describe a cross-shard leak."""
    collected = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None or not resp.get("Records"):
            break
        iterator = nxt
    return collected


CHECK = "at-sequence-number-from-foreign-shard-rejected"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AT_SEQUENCE_NUMBER with another shard's sequence number is an InvalidArgumentException.

    Sequence numbers are shard-scoped, so the iterator must not be built and the stream's shards
    stay unchanged; the same number on its own shard returns its record.
    """
    c = ctx.client("kinesis")
    expected_code = "InvalidArgumentException"

    name = _provisioned_stream(ctx, c, shard_count=2)
    shards_before = _shard_ids(c, name)
    assert len(shards_before) == 2, f"expected a 2-shard stream, ListShards gave {shards_before}"

    # Learn which shard took the record from the server; the other one is the foreign shard.
    put = _call_when_ready(
        lambda: c.put_record(StreamName=name, Data=b"owned-by-a", PartitionKey="pk-a")
    )
    shard_a = put["ShardId"]
    seq_a = put["SequenceNumber"]
    others = [s for s in shards_before if s != shard_a]
    assert len(others) == 1, f"could not identify a single foreign shard from {shards_before} vs {shard_a}"
    shard_b = others[0]

    # The same sequence number on its own shard works, so the refusal below is about the shard.
    own_it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_a,
        ShardIteratorType="AT_SEQUENCE_NUMBER", StartingSequenceNumber=seq_a,
    )["ShardIterator"]
    own_recs, _it, own_pages = _drain(c, own_it, want=1)
    assert [bytes(r["Data"]) for r in own_recs][:1] == [b"owned-by-a"], (
        f"control failed: AT_SEQUENCE_NUMBER({seq_a}) on its own shard {shard_a} returned "
        f"{[bytes(r['Data']) for r in own_recs]!r} over {own_pages} pages"
    )

    try:
        foreign = c.get_shard_iterator(
            StreamName=name, ShardId=shard_b,
            ShardIteratorType="AT_SEQUENCE_NUMBER", StartingSequenceNumber=seq_a,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == expected_code, (
            f"GetShardIterator(shard={shard_b}, AT_SEQUENCE_NUMBER={seq_a} minted on "
            f"{shard_a}) failed with {code}; expected {expected_code}"
        )
        # The message names the sequence number's own shard and the shard it was sent to.
        message = exc.response.get("Error", {}).get("Message", "")
        assert message == (
            f"Invalid StartingSequenceNumber. It encodes {shard_a}, while it was used in a call "
            f"to a shard with {shard_b}"
        ), f"GetShardIterator foreign-shard message: {message!r}"
    else:
        leaked = _drain_best_effort(c, foreign["ShardIterator"])
        raise AssertionError(
            f"GetShardIterator accepted shard {shard_a}'s sequence number {seq_a} for shard "
            f"{shard_b} and returned an iterator; expected {expected_code}. Reading it "
            f"yielded {[bytes(r['Data']) for r in leaked]!r} — a non-empty list here means "
            f"the emulator uses a global sequence counter and leaks records across shards"
        )

    shards_after = _shard_ids(c, name)
    assert shards_after == shards_before, (
        f"shard set changed across a refused GetShardIterator: {shards_before} -> {shards_after}"
    )
    open_shards = [
        s for s in c.list_shards(StreamName=name)["Shards"]
        if "EndingSequenceNumber" not in s["SequenceNumberRange"]
    ]
    assert len(open_shards) == 2, (
        f"expected both shards to remain open after the refusal, got "
        f"{[s['ShardId'] for s in open_shards]}"
    )

    again = c.get_shard_iterator(
        StreamName=name, ShardId=shard_b, ShardIteratorType="TRIM_HORIZON"
    )
    assert again["ShardIterator"], f"TRIM_HORIZON on {shard_b} stopped working after the refusal"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
