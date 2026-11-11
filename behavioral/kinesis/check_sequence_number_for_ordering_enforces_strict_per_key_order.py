"""sequence-number-for-ordering-enforces-strict-per-key-order."""
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


CHECK = "sequence-number-for-ordering-enforces-strict-per-key-order"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """Chaining SequenceNumberForOrdering strictly orders same-key PutRecords: each sequence number
    exceeds the one it was ordered on, and GetRecords returns the payloads in the chained order.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecord.html
    """
    c = ctx.client("kinesis")
    # Deliberately unsorted, so a target that sorts on read or stores records in a dict fails.
    payloads = [f"ord-{t}".encode() for t in ("m", "c", "z", "a", "q", "b", "y", "d", "n", "e")]
    assert payloads != sorted(payloads), (
        f"payload sequence {payloads!r} must not be sorted, or a sorting emulator passes"
    )

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    put_seqs = []
    ordered_on = []
    for i, payload in enumerate(payloads):
        kwargs = {"StreamName": name, "Data": payload, "PartitionKey": "same-key"}
        if put_seqs:
            kwargs["SequenceNumberForOrdering"] = put_seqs[-1]
        ordered_on.append(kwargs.get("SequenceNumberForOrdering"))
        resp = _call_when_ready(lambda k=dict(kwargs): c.put_record(**k))
        assert resp["ShardId"] == shard_id, (
            f"record {i} ({payload!r}) with the shared partition key landed on "
            f"{resp['ShardId']!r}, not the stream's only shard {shard_id!r}"
        )
        put_seqs.append(resp["SequenceNumber"])

    # The parameter's own contract: the record is placed strictly AFTER the sequence number it
    # was ordered on. Compared as integers — these are 128-bit decimals.
    for i in range(1, len(put_seqs)):
        assert int(put_seqs[i]) > int(ordered_on[i]), (
            f"PutRecord {i} was sent SequenceNumberForOrdering={ordered_on[i]!r} and was "
            f"assigned {put_seqs[i]!r}, which does not strictly follow it; the chain so far "
            f"was {put_seqs!r}"
        )

    as_ints = [int(s) for s in put_seqs]
    assert all(a < b for a, b in zip(as_ints, as_ints[1:])), (
        f"SequenceNumberForOrdering did not produce a strictly increasing chain: {put_seqs!r}"
    )

    iterator = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records, _next_it, pages = _drain(c, iterator, want=len(payloads))

    got = [bytes(r["Data"]) for r in records]
    assert got == payloads, (
        f"GetRecords returned {got!r} after draining {pages} pages; the chained write order "
        f"was {payloads!r}"
    )
    got_seqs = [r["SequenceNumber"] for r in records]
    assert got_seqs == put_seqs, (
        f"read-back sequence numbers {got_seqs!r} do not match the order the chain assigned "
        f"them, {put_seqs!r}"
    )
    assert len(records) == len(payloads), (
        f"{len(records)!r} records were read back from {len(payloads)!r} chained writes: {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
