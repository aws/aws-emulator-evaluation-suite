"""stream-record-creation-time-tracks-the-live-clock."""
from __future__ import annotations

import datetime as _dt
import math
import time

from behavioral_harness import tags

CHECK = "stream-record-creation-time-tracks-the-live-clock"
GROUP = "projection"
SERVICES = ["dynamodbstreams"]

# Forced separation between the two writes. ApproximateCreationDateTime is floored to the second,
# so two writes inside one second are INDISTINGUISHABLE and a strict-increase assertion over them
# would be a coin flip. 2.5 s guarantees the floored seconds differ whatever the sub-second phase.
_GAP_S = 2.5
# Tolerance for local-vs-AWS clock skew on the absolute bracket only.
_SKEW_S = 5.0
# Each endpoint floors independently (1 s), plus slack for when the service stamps the record.
_DIFF_SLACK_S = 2.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Each stream record's ApproximateCreationDateTime lies in its write's wall-clock bracket,
    is a whole second, and advances between two writes by no more than the measured gap.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_StreamRecord.html
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(
        ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbsclock-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "clock-item"}}

    # --- write A, bracketed by the live clock on both sides ---
    a_lo = time.time()
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "1"}})
    a_hi = time.time()
    first = _drain(streams, shard_ids, horizon, want=1)
    assert len(first) == 1, (
        f"the first write must produce exactly one stream record before the second write is "
        f"made, so the two records can be timed independently; drained {len(first)}"
    )
    shard_a, rec_a = first[0]

    # --- force a gap wider than the field's own second-granularity, then write B ---
    _wait_for_wall_clock_gap(since=a_hi, gap_s=_GAP_S)
    b_lo = time.time()
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "2"}})
    b_hi = time.time()
    measured_gap = b_lo - a_hi
    assert measured_gap >= _GAP_S, (
        f"the forced separation between the two writes must be at least {_GAP_S}s for the "
        f"strict-increase assertion below to be sound; measured {measured_gap:.3f}s"
    )

    cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard_a,
        ShardIteratorType="AFTER_SEQUENCE_NUMBER",
        SequenceNumber=rec_a["dynamodb"]["SequenceNumber"])["ShardIterator"]
    second = _drain(streams, [shard_a], [cursor], want=1)
    assert len(second) == 1, (
        f"the second write must arrive on the same shard {shard_a} after the first record's "
        f"sequence number; drained {len(second)}"
    )
    _shard_b, rec_b = second[0]

    # The two records really are the two writes, on one shard, in order.
    assert rec_a["eventName"] == "INSERT", (
        f"the first write to a fresh key is an INSERT, got {rec_a.get('eventName')!r}"
    )
    assert rec_b["eventName"] == "MODIFY", (
        f"the second write to the same key is a MODIFY, got {rec_b.get('eventName')!r}"
    )
    assert rec_a["dynamodb"]["Keys"] == key and rec_b["dynamodb"]["Keys"] == key, (
        f"both records must be for the key under test {key!r}; got "
        f"{rec_a['dynamodb'].get('Keys')!r} and {rec_b['dynamodb'].get('Keys')!r}"
    )
    assert int(rec_b["dynamodb"]["SequenceNumber"]) > int(rec_a["dynamodb"]["SequenceNumber"]), (
        f"the later write must carry the greater sequence number on one shard; got "
        f"{rec_a['dynamodb']['SequenceNumber']!r} then {rec_b['dynamodb']['SequenceNumber']!r}"
    )

    # --- absolute half: each timestamp inside the live bracket of its own write ---
    epoch_a = _assert_whole_second_timestamp(rec_a)
    epoch_b = _assert_whole_second_timestamp(rec_b)

    for label, epoch, lo, hi in (("INSERT", epoch_a, a_lo, a_hi), ("MODIFY", epoch_b, b_lo, b_hi)):
        # The lower bound is FLOORED because the field is documented as rounded down to the
        # closest second: a write at 10.9 s legitimately reports 10. That floor is required
        # correctness, not slack.
        floor_lo = math.floor(lo) - _SKEW_S
        ceil_hi = hi + _SKEW_S
        assert floor_lo <= epoch <= ceil_hi, (
            f"the {label} record's ApproximateCreationDateTime must fall inside the live "
            f"wall-clock bracket of the write that produced it, allowing {_SKEW_S}s of clock "
            f"skew: expected {floor_lo:.3f} <= t <= {ceil_hi:.3f} "
            f"({_dt.datetime.fromtimestamp(floor_lo, _dt.timezone.utc).isoformat()} .. "
            f"{_dt.datetime.fromtimestamp(ceil_hi, _dt.timezone.utc).isoformat()}), got "
            f"{epoch:.3f} "
            f"({_dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).isoformat()}), which is "
            f"{epoch - hi:+.3f}s from the moment PutItem returned"
        )

    # --- relative half: skew-free, because a constant clock offset cancels in a difference ---
    diff = epoch_b - epoch_a
    assert diff >= 1.0, (
        f"the two writes were separated by a measured {measured_gap:.3f}s of wall clock, which "
        f"is more than the field's one-second granularity, so the MODIFY record's timestamp must "
        f"be strictly later than the INSERT record's: expected a difference of at least 1s, got "
        f"{diff:.3f}s ({epoch_a:.3f} then {epoch_b:.3f}). A target that stamps a constant, or "
        f"copies the first record's timestamp forward, lands here"
    )
    assert diff <= measured_gap + _DIFF_SLACK_S, (
        f"the timestamps must advance by no MORE than the gap this run measured between the two "
        f"writes, allowing {_DIFF_SLACK_S}s for the field being floored at each end: expected a "
        f"difference of at most {measured_gap + _DIFF_SLACK_S:.3f}s, got {diff:.3f}s. A target "
        f"that stamps the record when it is READ rather than when it is written lands here"
    )


def _wait_for_wall_clock_gap(*, since: float, gap_s: float, timeout_s: float = 60.0) -> None:
    """Bounded wait until the wall clock has advanced ``gap_s`` past ``since``.

    Raises on timeout so a frozen clock fails loudly instead of weakening the assertion.
    """
    deadline = time.monotonic() + timeout_s
    while time.time() - since < gap_s:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the wall clock did not advance {gap_s}s within {timeout_s}s of monotonic time; "
                f"it reads {time.time():.3f} against a start of {since:.3f}. This check cannot "
                f"separate two writes without it"
            )
        time.sleep(0.25)


def _epoch_of(value) -> float:
    """Epoch seconds for whatever botocore handed back, without hiding the shape it used."""
    if isinstance(value, _dt.datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=_dt.timezone.utc)
        return aware.timestamp()
    assert isinstance(value, (int, float)), (
        f"ApproximateCreationDateTime must deserialise to a datetime (or, failing that, a "
        f"number of epoch seconds); got {type(value).__name__} {value!r}"
    )
    return float(value)


def _assert_whole_second_timestamp(record) -> float:
    """Assert the record's timestamp shape, then return it as epoch seconds."""
    label = record["eventName"]
    value = record["dynamodb"]["ApproximateCreationDateTime"]
    assert isinstance(value, _dt.datetime), (
        f"the {label} record's ApproximateCreationDateTime must deserialise to a datetime; got "
        f"{type(value).__name__} {value!r}"
    )
    assert value.tzinfo is not None, (
        f"the {label} record's ApproximateCreationDateTime must be timezone-aware so it can be "
        f"compared to a UTC clock without guessing an offset; got the naive value {value!r}"
    )
    assert value.microsecond == 0, (
        f"ApproximateCreationDateTime is documented as rounded down to the closest second, so it "
        f"must carry no sub-second component; the {label} record reported {value.isoformat()} "
        f"with microsecond={value.microsecond}. A target stamping datetime.now() straight "
        f"through lands here"
    )
    return _epoch_of(value)


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
    """Poll until DescribeStream reports shards AND every shard hands back an iterator.

    GetShardIterator can answer ResourceNotFoundException for a few seconds after the stream
    already reports ENABLED with shards.
    """
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


def _drain(streams, shard_ids: list, iterators: list, *, want: int, timeout_s: float = 120.0):
    """Follow every shard's NextShardIterator chain until ``want`` records are collected.

    A fresh iterator's first GetRecords can legitimately answer zero records, so this polls.
    """
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
