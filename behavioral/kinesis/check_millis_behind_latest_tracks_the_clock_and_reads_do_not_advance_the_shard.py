"""millis-behind-latest-tracks-the-clock-and-reads-do-not-advance-the-shard."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "millis-behind-latest-tracks-the-clock-and-reads-do-not-advance-the-shard"
GROUP = "data-plane"
SERVICES = ["kinesis"]

# MillisBehindLatest is how far behind current time the consumer is, so re-reading the SAME
# position after a measured interval raises it by about that interval. Host/service clock skew
# cancels out in the difference, which is why the assertion is on the delta.

_N_RECORDS = 6
_PAYLOADS = tuple(f"lag-probe-{i}".encode() for i in range(_N_RECORDS))
_PARTITION_KEY = "lag-pk"

#: Lag must become at least this large before the delta leg starts, so the delta is measurable.
_MIN_BEHIND_MS = 2000
#: How much further the reported lag must grow while the read position stays put.
_DELTA_MS = 4000
_DELTA_TOLERANCE_MS = 2000
#: A read must not advance the shard: N consecutive identical reads, no timing assumption.
_FREEZE_READS = 3


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """MillisBehindLatest is a live measurement, not a constant: held at one position it grows by
    the elapsed wall-clock time, it is strictly positive for an older record and exactly zero at the
    tip, and the reads that measure it never consume the shard."""
    kinesis = ctx.client("kinesis")
    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])

    put_seqs = [
        kinesis.put_record(
            StreamName=stream["name"], Data=payload, PartitionKey=_PARTITION_KEY
        )["SequenceNumber"]
        for payload in _PAYLOADS
    ]
    assert len(set(put_seqs)) == _N_RECORDS, (
        f"PutRecord returned duplicate sequence numbers {put_seqs}; expected {_N_RECORDS} distinct"
    )

    pinned = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    # ---- (a) Lag is reported at all, and becomes strictly positive as the records age ----
    # The success condition IS the assertion: a target that hardcodes MillisBehindLatest == 0 can
    # never satisfy it and the poll raises.
    first = _poll_until(
        lambda: _get_records(kinesis, pinned, limit=1),
        lambda r: r["Records"] and r["MillisBehindLatest"] >= _MIN_BEHIND_MS,
        timeout_s=60.0,
        interval_s=1.0,
        description=(
            f"a TRIM_HORIZON read of {shard_id} to report MillisBehindLatest >= {_MIN_BEHIND_MS} as "
            "the records it returns age"
        ),
    )
    lag_1 = first["MillisBehindLatest"]
    # Start the clock at the instant lag_1 was measured, not after the freeze loop below; a later
    # start would exclude those seconds from elapsed_ms and undercount the lag growth.
    started = time.monotonic()
    frozen_seqs = [r["SequenceNumber"] for r in first["Records"]]
    assert frozen_seqs == put_seqs[: len(frozen_seqs)], (
        f"the TRIM_HORIZON read returned sequence numbers {frozen_seqs}; expected the first "
        f"{len(frozen_seqs)} PutRecord sequence numbers {put_seqs[: len(frozen_seqs)]}"
    )

    # ---- (b) Freeze detector: reads must not advance the shard ----
    for attempt in range(_FREEZE_READS):
        repeat = _get_records(kinesis, pinned, limit=1)
        repeat_seqs = [r["SequenceNumber"] for r in repeat["Records"]]
        assert repeat_seqs == frozen_seqs, (
            f"re-read {attempt + 1} of {_FREEZE_READS} on the SAME shard iterator returned "
            f"{repeat_seqs}; expected the identical {frozen_seqs} — GetRecords is a read and must "
            "not consume or advance the shard"
        )
        time.sleep(1.0)  # 5 TPS/shard cap; bounded by the loop, not a wait for an effect.

    # ---- (c) The derivation rule: lag tracks the live clock while the position stays put ----
    later = _poll_until(
        lambda: _get_records(kinesis, pinned, limit=1),
        lambda r: r["MillisBehindLatest"] >= lag_1 + _DELTA_MS,
        timeout_s=3.0 * (_DELTA_MS / 1000.0) + 15.0,
        interval_s=1.0,
        description=(
            f"MillisBehindLatest at the pinned position to grow from {lag_1} by at least "
            f"{_DELTA_MS} ms — a target that reports a CONSTANT lag can never satisfy this"
        ),
    )
    elapsed_ms = (time.monotonic() - started) * 1000.0
    lag_2 = later["MillisBehindLatest"]
    growth = lag_2 - lag_1
    assert abs(growth - elapsed_ms) <= _DELTA_TOLERANCE_MS, (
        f"MillisBehindLatest grew by {growth} ms while {elapsed_ms:.0f} ms of wall clock elapsed at "
        f"an UNCHANGED read position (lag {lag_1} -> {lag_2}); the two must agree within "
        f"{_DELTA_TOLERANCE_MS} ms because the reported lag is the age of the last returned record"
    )
    later_seqs = [r["SequenceNumber"] for r in later["Records"]]
    assert later_seqs == frozen_seqs, (
        f"the delta read returned {later_seqs}; expected the same {frozen_seqs} — only the reported "
        "lag may change, never the position"
    )

    # ---- (d) Two-sided: positive behind the tip, exactly zero at it ----
    iterator = pinned
    seen: list[str] = []
    last_with_records = None
    empty_at_tip = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        resp = _get_records(kinesis, iterator, limit=1)
        if resp["Records"]:
            seen.extend(r["SequenceNumber"] for r in resp["Records"])
            last_with_records = resp
        elif len(seen) >= _N_RECORDS:
            empty_at_tip = resp
            break
        next_iterator = resp.get("NextShardIterator")
        assert next_iterator, (
            f"NextShardIterator was null on the OPEN shard {shard_id} after reading {len(seen)} of "
            f"{_N_RECORDS} records; a null NextShardIterator means the shard is closed"
        )
        iterator = next_iterator
        time.sleep(1.0)  # 5 TPS/shard cap.
    assert empty_at_tip is not None, (
        f"never reached the tip of {shard_id} within 120s: read {len(seen)} of {_N_RECORDS} records "
        "and never got an empty response"
    )
    assert seen == put_seqs, (
        f"draining {shard_id} one record at a time yielded sequence numbers {seen}; expected exactly "
        f"the {_N_RECORDS} written, in order: {put_seqs}"
    )
    assert last_with_records["MillisBehindLatest"] > 0, (
        "the response carrying the LAST record reported MillisBehindLatest "
        f"{last_with_records['MillisBehindLatest']}; that record was written seconds earlier, so the "
        "reported lag must be strictly positive"
    )
    assert empty_at_tip["MillisBehindLatest"] == 0, (
        f"the response AT the tip (zero records, all {_N_RECORDS} consumed) reported "
        f"MillisBehindLatest {empty_at_tip['MillisBehindLatest']}; a caught-up consumer must be "
        "reported as exactly 0"
    )

    # ---- Terminal independent read: none of those reads consumed the shard ----
    fresh = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    replayed = _poll_until(
        lambda: _get_records(kinesis, fresh, limit=1000),
        lambda r: len(r["Records"]) >= _N_RECORDS,
        timeout_s=60.0,
        interval_s=1.0,
        description=f"all {_N_RECORDS} records to still be readable from a FRESH TRIM_HORIZON "
        f"iterator on {shard_id} after the full drain above",
    )
    replayed_seqs = [r["SequenceNumber"] for r in replayed["Records"]]
    assert replayed_seqs == put_seqs, (
        f"a fresh TRIM_HORIZON iterator returned {replayed_seqs} after the shard was drained "
        f"record-by-record; expected all {_N_RECORDS} originals {put_seqs} — a Kinesis shard is a "
        "log, not a queue, and reading it destroys nothing"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _get_records(kinesis, iterator: str, *, limit: int) -> dict:
    """GetRecords, retrying only the documented 5-TPS-per-shard throttle."""
    for attempt in range(6):
        try:
            return kinesis.get_records(ShardIterator=iterator, Limit=limit)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ProvisionedThroughputExceededException":
                raise
            if attempt == 5:
                raise
            time.sleep(1.0 + attempt)
    raise AssertionError("unreachable: the retry loop above either returns or raises")


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"stream {name} to reach ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _single_shard_id(ctx, stream_name: str) -> str:
    """ListShards can lag ACTIVE briefly; poll until exactly one shard is addressable."""
    kinesis = ctx.client("kinesis")

    def probe() -> list:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceInUseException", "ResourceNotFoundException"):
                return []
            raise

    shards = _poll_until(
        probe,
        lambda s: len(s) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"exactly one shard to be addressable on {stream_name}",
    )
    return shards[0]["ShardId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
