"""closed-shard-get-records-ends-with-a-null-next-shard-iterator."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "closed-shard-get-records-ends-with-a-null-next-shard-iterator"
GROUP = "lifecycle"
SERVICES = ["dynamodbstreams"]

_WRITES = 4
_FREEZE_READS = 3
_CLOSED_DRAIN_S = 120.0


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A closed shard signals end-of-data by omitting NextShardIterator, while the same past-the-end
    read on the shard while open returns an empty page with an iterator; a closed shard still
    replays all its records in order.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetRecords.html
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(
        ctx, ddb, "NEW_AND_OLD_IMAGES", "sim2real-behav-dbsnull-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "null-iterator-item"}}
    for n in range(1, _WRITES + 1):
        ddb.put_item(TableName=table, Item={**key, "v": {"N": str(n)}})

    tagged = _drain(streams, shard_ids, horizon, want=_WRITES)
    assert len(tagged) == _WRITES, (
        f"all {_WRITES} writes must reach the stream before the shard is closed; drained "
        f"{len(tagged)} records"
    )
    landed = {shard for shard, _rec in tagged}
    assert len(landed) == 1, (
        f"all writes to one partition key must land on ONE shard for the open/closed twin below "
        f"to compare like with like; they landed on {sorted(landed)!r}"
    )
    shard = landed.pop()
    seqs = [rec["dynamodb"]["SequenceNumber"] for _s, rec in tagged]
    written = [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in tagged]
    expected = [str(n) for n in range(1, _WRITES + 1)]
    assert written == expected, (
        f"the shard must replay the writes in order before it is closed; expected {expected!r}, "
        f"got {written!r}"
    )

    # Open shard: an empty page is not an end, so every past-the-end read still returns an iterator.
    cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard,
        ShardIteratorType="AFTER_SEQUENCE_NUMBER", SequenceNumber=seqs[-1])["ShardIterator"]
    for attempt in range(1, _FREEZE_READS + 1):
        resp = streams.get_records(ShardIterator=cursor)
        assert resp.get("Records") == [], (
            f"read {attempt} of {_FREEZE_READS} past the end of the OPEN shard {shard} must "
            f"yield no records, got "
            f"{[r['dynamodb']['NewImage']['v']['N'] for r in resp.get('Records', [])]!r}"
        )
        assert "NextShardIterator" in resp and resp["NextShardIterator"], (
            f"read {attempt} of {_FREEZE_READS}: an OPEN shard read past its end must still hand "
            f"back a NextShardIterator -- an empty page is not an end-of-shard signal. Response "
            f"held {sorted(resp)!r}"
        )
        cursor = resp["NextShardIterator"]

    ddb.update_table(TableName=table, StreamSpecification={"StreamEnabled": False})
    disabled = _poll(
        lambda: streams.describe_stream(StreamArn=stream_arn)["StreamDescription"],
        # Non-empty first: all() over an empty shard list is vacuously True.
        lambda d: d["StreamStatus"] == "DISABLED"
        and bool(d.get("Shards"))
        and all("EndingSequenceNumber" in s["SequenceNumberRange"] for s in d["Shards"]),
        timeout_s=240.0,
        description=(
            "an independent DescribeStream reports the stream DISABLED with an "
            "EndingSequenceNumber on every shard -- the structural barrier this check's "
            "absence assertions are bounded by"
        ),
    )
    closed = {s["ShardId"]: s for s in disabled["Shards"]}
    assert shard in closed, (
        f"the shard that took the writes ({shard}) must survive its own disabling and still be "
        f"described; DescribeStream now reports {sorted(closed)!r}"
    )
    ending = closed[shard]["SequenceNumberRange"].get("EndingSequenceNumber", "")
    assert ending.isdigit(), (
        f"shard {shard} must be marked CLOSED by a numeric EndingSequenceNumber; "
        f"SequenceNumberRange is {closed[shard]['SequenceNumberRange']!r}"
    )
    assert int(ending) >= int(seqs[-1]), (
        f"the shard's EndingSequenceNumber ({ending}) must be at least the sequence number of "
        f"the last record it accepted ({seqs[-1]}), or the closure excludes records the shard "
        f"still serves"
    )

    # The identical past-the-end read on the closed shard. botocore drops a null member, so the
    # documented null NextShardIterator surfaces as an absent key.
    closed_cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard,
        ShardIteratorType="AFTER_SEQUENCE_NUMBER", SequenceNumber=seqs[-1])["ShardIterator"]
    tail_records, tail_final, tail_pages = _drain_until_null(
        streams, closed_cursor, timeout_s=_CLOSED_DRAIN_S, subject=f"{shard} past its last record")
    assert tail_records == [], (
        f"a CLOSED shard read from AFTER its last record must yield nothing, got "
        f"{[r['dynamodb'].get('Keys') for r in tail_records]!r} over {tail_pages} pages"
    )
    assert "NextShardIterator" not in tail_final, (
        f"the terminal GetRecords page on CLOSED shard {shard} must OMIT NextShardIterator -- "
        f"that null is the only end-of-data signal a consumer has, and the identical call on "
        f"this same shard while it was OPEN returned one. Response held {sorted(tail_final)!r} "
        f"after {tail_pages} pages"
    )

    replay_cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard,
        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    full_records, full_final, full_pages = _drain_until_null(
        streams, replay_cursor, timeout_s=_CLOSED_DRAIN_S,
        subject=f"{shard} from TRIM_HORIZON to exhaustion")
    replayed = [r["dynamodb"]["NewImage"]["v"]["N"] for r in full_records]
    assert replayed == expected, (
        f"draining CLOSED shard {shard} to exhaustion must yield exactly the records it holds, "
        f"in write order, with no gaps and no duplicates: expected {expected!r}, got "
        f"{replayed!r} over {full_pages} pages"
    )
    assert "NextShardIterator" not in full_final, (
        f"the final page of a full drain of CLOSED shard {shard} must OMIT NextShardIterator; "
        f"response held {sorted(full_final)!r}. A consumer that never sees this null re-reads "
        f"the shard forever and never advances to the child shard"
    )
    replayed_seqs = [r["dynamodb"]["SequenceNumber"] for r in full_records]
    assert replayed_seqs == seqs, (
        f"the closed shard must replay the SAME sequence numbers the open shard issued; "
        f"expected {seqs!r}, got {replayed_seqs!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 3.0, description: str = "condition"):
    """Bounded retry that RAISES on timeout; never returns an unsatisfied value."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


def _drain_until_null(streams, cursor: str, *, timeout_s: float, subject: str,
                      interval_s: float = 2.0):
    """Chain GetRecords through empty pages until the response omits NextShardIterator.

    Returns ``(records, final_response, pages)``; raises at the deadline.
    """
    records: list = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = streams.get_records(ShardIterator=cursor)
        pages += 1
        records.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if not nxt:
            return records, resp, pages
        cursor = nxt
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"CLOSED shard {subject} never omitted NextShardIterator: chained {pages} "
                f"GetRecords pages over {timeout_s}s and collected {len(records)} records. "
                f"Without that terminal null a consumer loops on this shard forever and never "
                f"advances to its child"
            )
        time.sleep(interval_s)


def _create_stream_table(ctx, ddb, view_type: str, prefix: str) -> tuple[str, str]:
    name = ctx.unique_name(prefix)
    created = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": view_type},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    stream_arn = created["TableDescription"]["LatestStreamArn"]
    assert stream_arn, (
        f"CreateTable with StreamEnabled must mint a LatestStreamArn, got "
        f"{created['TableDescription'].get('LatestStreamArn')!r}"
    )
    return name, stream_arn


def _wait_stream_usable(streams, stream_arn: str, timeout_s: float = 180.0):
    """Poll until DescribeStream reports shards and every shard hands back an iterator; an
    ENABLED stream can still answer GetShardIterator with ResourceNotFoundException briefly."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
        shard_ids = [s["ShardId"] for s in desc.get("Shards", [])]
        if shard_ids:
            try:
                iterators = [
                    streams.get_shard_iterator(
                        StreamArn=stream_arn, ShardId=sid,
                        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
                    for sid in shard_ids
                ]
            except ClientError as exc:
                last = exc.response["Error"]["Code"]
                if last != "ResourceNotFoundException":
                    raise
            else:
                return desc, shard_ids, iterators
        else:
            last = f"{desc.get('StreamStatus')} with 0 shards"
        time.sleep(2.0)
    raise AssertionError(
        f"stream {stream_arn} never became readable within {timeout_s}s; last state {last!r}"
    )


def _drain(streams, shard_ids: list, iterators: list, *, want: int, timeout_s: float = 150.0):
    """Follow every shard's NextShardIterator chain until ``want`` records are collected; a fresh
    iterator's first GetRecords can legitimately return zero records."""
    tagged: list = []
    cursors = list(iterators)
    deadline = time.monotonic() + timeout_s
    while len(tagged) < want and time.monotonic() < deadline:
        progressed = False
        for i, cursor in enumerate(cursors):
            if cursor is None:
                continue
            resp = streams.get_records(ShardIterator=cursor)
            got = resp.get("Records", [])
            if got:
                tagged.extend((shard_ids[i], rec) for rec in got)
                progressed = True
            cursors[i] = resp.get("NextShardIterator")
        if len(tagged) >= want or not any(cursors):
            break
        if not progressed:
            time.sleep(2.0)
    return tagged


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
