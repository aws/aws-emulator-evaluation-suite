"""at-timestamp-iterator-clamps-to-earliest-record."""
from __future__ import annotations

import datetime
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


def _arrival(records, payload):
    for r in records:
        if bytes(r["Data"]) == payload:
            return r["ApproximateArrivalTimestamp"]
    raise AssertionError(f"record {payload!r} not among {[bytes(r['Data']) for r in records]!r}")


CHECK = "at-timestamp-iterator-clamps-to-earliest-record"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AT_TIMESTAMP before the oldest record clamps to it instead of erroring or reading empty.

    ApproximateArrivalTimestamp advances per record, and AT_TIMESTAMP at the second record's
    arrival is inclusive of it and excludes the first.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]

    _call_when_ready(lambda: c.put_record(StreamName=name, Data=b"first", PartitionKey="k"))
    # Read the first record back before writing the second so the two arrival timestamps are
    # separated by a real wall-clock gap.
    horizon = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    first_only, _it, _pages = _drain(c, horizon, want=1)
    t_first = _arrival(first_only, b"first")

    _poll(lambda: datetime.datetime.now(datetime.timezone.utc),
          lambda now: (now - t_first).total_seconds() >= 2.0,
          timeout_s=20, interval_s=0.5,
          description="a >=2s wall-clock gap after the first record's arrival")
    c.put_record(StreamName=name, Data=b"second", PartitionKey="k")

    horizon2 = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    both, _it, _pages = _drain(c, horizon2, want=2)
    assert [bytes(r["Data"]) for r in both] == [b"first", b"second"], (
        f"precondition failed: TRIM_HORIZON read {[bytes(r['Data']) for r in both]!r}"
    )
    t_second = _arrival(both, b"second")
    assert t_second > t_first, (
        f"ApproximateArrivalTimestamp must advance between records, got first={t_first} "
        f"second={t_second} (an emulator stamping a constant time fails here)"
    )

    way_back = t_first - datetime.timedelta(hours=1)
    clamped_it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id,
        ShardIteratorType="AT_TIMESTAMP", Timestamp=way_back,
    )["ShardIterator"]
    clamped, _it, clamped_pages = _drain(c, clamped_it, want=2)
    clamped_data = [bytes(r["Data"]) for r in clamped]
    assert clamped_data == [b"first", b"second"], (
        f"AT_TIMESTAMP({way_back.isoformat()}), one hour before the oldest record, returned "
        f"{clamped_data!r} over {clamped_pages} pages; it must clamp to the trim horizon and "
        f"yield [b'first', b'second'], not error and not return an empty shard"
    )

    # Excluding the first record shows the clamp above is not "AT_TIMESTAMP always replays all".
    at_second_it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id,
        ShardIteratorType="AT_TIMESTAMP", Timestamp=t_second,
    )["ShardIterator"]
    at_second, _it, at_pages = _drain(c, at_second_it, want=1)
    at_second_data = [bytes(r["Data"]) for r in at_second]
    assert b"second" in at_second_data, (
        f"AT_TIMESTAMP({t_second.isoformat()}) must be inclusive of the record that arrived "
        f"at that instant, got {at_second_data!r} over {at_pages} pages"
    )
    assert b"first" not in at_second_data, (
        f"AT_TIMESTAMP({t_second.isoformat()}) replayed the earlier record: "
        f"{at_second_data!r}; positioning by timestamp is not being honoured"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
