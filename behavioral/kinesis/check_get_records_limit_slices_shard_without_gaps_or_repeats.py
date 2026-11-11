"""get-records-limit-slices-shard-without-gaps-or-repeats."""
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



CHECK = "get-records-limit-slices-shard-without-gaps-or-repeats"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """GetRecords(Limit=2) walks a shard in exact order with no gap, no repeat and no loss, and a
    second Limit-less read from TRIM_HORIZON returns the identical sequence (reads consume nothing).
    """
    c = ctx.client("kinesis")
    payloads = [f"pg-{t}".encode() for t in ("m", "c", "z", "a", "q", "b")]
    assert payloads != sorted(payloads), (
        f"payload sequence {payloads!r} must not be sorted, or a sorting emulator passes"
    )
    limit = 2  # 6 records over Limit=2 forces at least three page boundaries.

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    for i, payload in enumerate(payloads):
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="same-key")
        )
        assert resp["ShardId"] == shard_id, (
            f"record {i} ({payload!r}) landed on {resp['ShardId']!r}, not the only shard "
            f"{shard_id!r}"
        )

    iterator = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    pages = []
    sliced = []
    deadline = time.monotonic() + 180
    while len(sliced) < len(payloads):
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        page = [bytes(r["Data"]) for r in resp.get("Records", [])]
        assert len(page) <= limit, (
            f"GetRecords returned {len(page)} records for Limit={limit}: {page!r}"
        )
        pages.append(page)
        sliced.extend(page)
        nxt = resp.get("NextShardIterator")
        assert nxt is not None, (
            f"GetRecords omitted NextShardIterator on page {len(pages)} of an OPEN shard "
            f"({shard_id!r}); a null NextShardIterator means the shard is CLOSED, and this one "
            f"was never resharded. Pages so far: {pages!r}"
        )
        iterator = nxt
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"read {len(pages)} pages of Limit={limit} over 180s and collected "
                f"{len(sliced)} of {len(payloads)} records: {pages!r}"
            )

    assert sliced == payloads, (
        f"the Limit={limit} pages concatenated to {sliced!r} over {pages!r}; the shard's "
        f"produced order is {payloads!r}, so the pages must tile it exactly"
    )
    assert len(sliced) == len(set(sliced)), (
        f"a record was served by more than one page: pages were {pages!r}. Chaining "
        f"NextShardIterator must advance past everything the previous page returned"
    )
    assert len(pages) >= len(payloads) // limit, (
        f"{len(payloads)} records at Limit={limit} needs at least "
        f"{len(payloads) // limit} pages, but only {len(pages)} were read: {pages!r} — Limit "
        f"was not applied"
    )

    # Having consumed the shard, the iterator still advances on an open shard and serves nothing
    # further: an exhausted subscription must not re-deliver.
    tail = c.get_records(ShardIterator=iterator, Limit=limit)
    assert [bytes(r["Data"]) for r in tail.get("Records", [])] == [], (
        f"after all {len(payloads)} records were paged out, the next page returned "
        f"{[bytes(r['Data']) for r in tail.get('Records', [])]!r}; the shard holds nothing more"
    )
    assert tail.get("NextShardIterator") is not None, (
        "an open shard's GetRecords always returns a NextShardIterator to continue from, even "
        "when the page is empty; this one returned none"
    )

    # GetRecords is a read: a second, Limit-less pass from TRIM_HORIZON must return the same
    # sequence. This is what makes the tiling above a property of the shard, not of one walk.
    reread_it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    reread, _next_it, reread_pages = _drain(c, reread_it, want=len(payloads))
    assert [bytes(r["Data"]) for r in reread] == payloads, (
        f"re-reading the shard from TRIM_HORIZON over {reread_pages} unbounded pages returned "
        f"{[bytes(r['Data']) for r in reread]!r}, not the same sequence the Limit={limit} walk "
        f"produced ({payloads!r}); GetRecords consumes nothing, so the two reads must agree"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
