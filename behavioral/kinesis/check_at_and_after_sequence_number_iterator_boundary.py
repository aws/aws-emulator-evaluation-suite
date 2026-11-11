"""at-and-after-sequence-number-iterator-boundary."""
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
        c, name, ShardCount=shard_count, StreamModeDetails={"StreamMode": "PROVISIONED"}
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


CHECK = "at-and-after-sequence-number-iterator-boundary"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AT_SEQUENCE_NUMBER starts at the named record and AFTER_SEQUENCE_NUMBER at the one after it, so the two
    reads differ by exactly that record: the off-by-one a checkpointing consumer relies on to resume without
    duplicating or dropping a record."""
    c = ctx.client("kinesis")
    payloads = [b"p-0", b"p-1", b"p-2", b"p-3"]

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]

    seqs = []
    for payload in payloads:
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="k")
        )
        seqs.append(resp["SequenceNumber"])

    # Establish the records are all readable before slicing, so an empty AT_* page is a
    # real defect and not just propagation lag.
    horizon = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    all_recs, _it, _pages = _drain(c, horizon, want=len(payloads))
    assert [bytes(r["Data"]) for r in all_recs] == payloads, (
        f"precondition failed: TRIM_HORIZON read {[bytes(r['Data']) for r in all_recs]!r}, "
        f"expected {payloads!r}"
    )

    at_it = c.get_shard_iterator(
        StreamName=name,
        ShardId=shard_id,
        ShardIteratorType="AT_SEQUENCE_NUMBER",
        StartingSequenceNumber=seqs[1],
    )["ShardIterator"]
    at_recs, _it, at_pages = _drain(c, at_it, want=3)
    at_data = [bytes(r["Data"]) for r in at_recs]
    assert at_data == payloads[1:], (
        f"AT_SEQUENCE_NUMBER({seqs[1]}) returned {at_data!r} over {at_pages} pages; "
        f"it must be inclusive of that record, i.e. {payloads[1:]!r}"
    )
    assert at_recs[0]["SequenceNumber"] == seqs[1], (
        f"AT_SEQUENCE_NUMBER's first record has SequenceNumber "
        f"{at_recs[0]['SequenceNumber']}, expected the named {seqs[1]}"
    )
    assert payloads[0] not in at_data, (
        f"AT_SEQUENCE_NUMBER({seqs[1]}) leaked the earlier record {payloads[0]!r}: {at_data!r}"
    )

    after_it = c.get_shard_iterator(
        StreamName=name,
        ShardId=shard_id,
        ShardIteratorType="AFTER_SEQUENCE_NUMBER",
        StartingSequenceNumber=seqs[1],
    )["ShardIterator"]
    after_recs, _it, after_pages = _drain(c, after_it, want=2)
    after_data = [bytes(r["Data"]) for r in after_recs]
    assert after_data == payloads[2:], (
        f"AFTER_SEQUENCE_NUMBER({seqs[1]}) returned {after_data!r} over {after_pages} "
        f"pages; it must be exclusive of that record, i.e. {payloads[2:]!r}"
    )
    assert payloads[1] not in after_data, (
        f"AFTER_SEQUENCE_NUMBER({seqs[1]}) re-delivered the named record "
        f"{payloads[1]!r}, which would duplicate a checkpointed record: {after_data!r}"
    )
    assert after_recs[0]["SequenceNumber"] == seqs[2], (
        f"AFTER_SEQUENCE_NUMBER's first record has SequenceNumber "
        f"{after_recs[0]['SequenceNumber']}, expected the next one {seqs[2]}"
    )
    assert len(at_data) == len(after_data) + 1, (
        f"AT_ and AFTER_ must differ by exactly one record, got {len(at_data)} vs "
        f"{len(after_data)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
