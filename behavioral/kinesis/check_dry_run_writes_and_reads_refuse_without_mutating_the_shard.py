"""dry-run-writes-and-reads-refuse-without-mutating-the-shard."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dry-run-writes-and-reads-refuse-without-mutating-the-shard"
GROUP = "server-side"
SERVICES = ["kinesis"]

# GetRecords is limited to 5 transactions per second per shard, so the reads are paced at 1 s.

_REAL_FIRST = b"dry-run-real-first"
_REAL_SECOND = b"dry-run-real-second"
_GHOST_SINGLE = b"dry-run-ghost-single"
_GHOST_BATCH = tuple(f"dry-run-ghost-batch-{i}".encode() for i in range(3))
_PARTITION_KEY = "dry-run-pk"


def _dry_run_refusal(operation: str) -> tuple[str, str]:
    """The exact (code, message) Kinesis returns for a DryRun=True call to ``operation``."""
    return (
        "DryRunOperationException",
        f"DryRunOperation validation succeeded while calling {operation} operation.: "
        "Request would have succeeded, but DryRun flag is set.",
    )


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """DryRun=True on the Kinesis data plane refuses with DryRunOperationException and leaves the
    shard byte-for-byte unchanged: no ghost record is appended, and no read position moves."""
    kinesis = ctx.client("kinesis")
    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])

    # ---- Positive control: the identical write path works on this wiring ----
    real_first_seq = kinesis.put_record(
        StreamName=stream["name"], Data=_REAL_FIRST, PartitionKey=_PARTITION_KEY
    )["SequenceNumber"]
    assert real_first_seq, "positive control: PutRecord returned an empty SequenceNumber"
    payloads = _read_all(ctx, stream["name"], shard_id, expect=1)
    assert payloads == [_REAL_FIRST], (
        f"positive control: a TRIM_HORIZON read returned {payloads!r}; expected exactly "
        f"[{_REAL_FIRST!r}]"
    )

    # ---- Break exactly one thing: add DryRun to the same PutRecord ----
    err = _client_error(
        lambda: kinesis.put_record(
            StreamName=stream["name"],
            Data=_GHOST_SINGLE,
            PartitionKey=_PARTITION_KEY,
            DryRun=True,
        )
    )
    refused = (err.get("Code"), err.get("Message"))
    assert refused == _dry_run_refusal("PutRecord"), (
        f"PutRecord with DryRun=True must be refused with {_dry_run_refusal('PutRecord')!r}, got {refused!r}"
    )

    # ---- Effect absent, via an independent read at the shard ----
    payloads = _read_all(ctx, stream["name"], shard_id, expect=1)
    assert payloads == [_REAL_FIRST], (
        f"after a dry-run PutRecord the shard reads back {payloads!r}; expected the single real "
        f"record [{_REAL_FIRST!r}] — a dry run must append nothing. "
        f"{_GHOST_SINGLE!r} present means DryRun was ignored"
    )

    # ---- Same shape for PutRecords: a whole batch must vanish ----
    err = _client_error(
        lambda: kinesis.put_records(
            StreamName=stream["name"],
            Records=[{"Data": data, "PartitionKey": _PARTITION_KEY} for data in _GHOST_BATCH],
            DryRun=True,
        )
    )
    refused = (err.get("Code"), err.get("Message"))
    assert refused == _dry_run_refusal("PutRecords"), (
        f"PutRecords with DryRun=True must be refused with {_dry_run_refusal('PutRecords')!r}, got {refused!r}"
    )
    payloads = _read_all(ctx, stream["name"], shard_id, expect=1)
    assert payloads == [_REAL_FIRST], (
        f"after a dry-run PutRecords of {len(_GHOST_BATCH)} entries the shard reads back "
        f"{payloads!r}; expected the single real record [{_REAL_FIRST!r}]"
    )

    # ---- Restore: the identical write without DryRun succeeds and IS visible ----
    real_second_seq = kinesis.put_record(
        StreamName=stream["name"], Data=_REAL_SECOND, PartitionKey=_PARTITION_KEY
    )["SequenceNumber"]
    assert int(real_second_seq) > int(real_first_seq), (
        f"the second real record's sequence number {real_second_seq} is not greater than the "
        f"first's {real_first_seq}; per-shard sequence numbers must increase"
    )
    payloads = _read_all(ctx, stream["name"], shard_id, expect=2)
    assert payloads == [_REAL_FIRST, _REAL_SECOND], (
        f"after restoring the non-dry-run write the shard reads back {payloads!r}; expected "
        f"[{_REAL_FIRST!r}, {_REAL_SECOND!r}] in write order"
    )

    # ---- GetShardIterator: DryRun refuses, the identical call without it yields a usable iterator ----
    err = _client_error(
        lambda: kinesis.get_shard_iterator(
            StreamName=stream["name"],
            ShardId=shard_id,
            ShardIteratorType="TRIM_HORIZON",
            DryRun=True,
        )
    )
    refused = (err.get("Code"), err.get("Message"))
    assert refused == _dry_run_refusal("GetShardIterator"), (
        f"GetShardIterator with DryRun=True must be refused with {_dry_run_refusal('GetShardIterator')!r}, got {refused!r}"
    )
    iterator = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    assert iterator, "the identical GetShardIterator call without DryRun returned no ShardIterator"

    # ---- GetRecords: DryRun refuses AND does not advance the position ----
    before = _get_records(kinesis, iterator, limit=1000)
    before_seqs = [r["SequenceNumber"] for r in before["Records"]]
    assert before_seqs == [real_first_seq, real_second_seq], (
        f"positive control: GetRecords returned {before_seqs}; expected "
        f"{[real_first_seq, real_second_seq]}"
    )

    err = _client_error(
        lambda: kinesis.get_records(ShardIterator=iterator, Limit=1000, DryRun=True)
    )
    refused = (err.get("Code"), err.get("Message"))
    assert refused == _dry_run_refusal("GetRecords"), (
        f"GetRecords with DryRun=True must be refused with {_dry_run_refusal('GetRecords')!r}, got {refused!r}"
    )

    time.sleep(1.0)  # 5 TPS/shard cap; a pacer, not a wait for an effect.
    after = _get_records(kinesis, iterator, limit=1000)
    after_seqs = [r["SequenceNumber"] for r in after["Records"]]
    assert after_seqs == before_seqs, (
        f"reusing the SAME iterator after a refused dry-run GetRecords returned {after_seqs}; "
        f"expected the identical {before_seqs} — a refused read must not advance the position"
    )

    # ---- Terminal independent read: exactly the real records, none of the ghosts ----
    final = _read_all(ctx, stream["name"], shard_id, expect=2)
    assert final == [_REAL_FIRST, _REAL_SECOND], (
        f"the shard's final contents are {final!r}; expected exactly the two records written "
        f"without DryRun. Any of {_GHOST_SINGLE!r} or {[*_GHOST_BATCH]!r} present means a dry run "
        "mutated the stream"
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


def _client_error(fn) -> dict:
    """Return the botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _get_records(kinesis, iterator: str, *, limit: int) -> dict:
    """GetRecords, retrying only the documented 5-TPS-per-shard throttle."""
    for attempt in range(6):
        try:
            return kinesis.get_records(ShardIterator=iterator, Limit=limit)
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code")
                != "ProvisionedThroughputExceededException"
            ):
                raise
            if attempt == 5:
                raise
            time.sleep(1.0 + attempt)
    raise AssertionError("unreachable: the retry loop above either returns or raises")


def _read_all(ctx, stream_name: str, shard_id: str, *, expect: int) -> list[bytes]:
    """Read the shard from TRIM_HORIZON with a FRESH iterator and return every payload.

    Waits until at least `expect` records are visible (read-after-write on a shard is not instant),
    then returns everything read so a caller asserting an EXACT list can also catch extras.
    """
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    collected: list[bytes] = []
    state = {"iterator": iterator}

    def probe() -> int:
        resp = _get_records(kinesis, state["iterator"], limit=1000)
        collected.extend(r["Data"] for r in resp["Records"])
        state["iterator"] = resp.get("NextShardIterator") or state["iterator"]
        return len(collected)

    _poll_until(
        probe,
        lambda n: n >= expect,
        timeout_s=60.0,
        interval_s=1.0,
        description=f"{expect} records to be readable from {shard_id}",
    )
    return collected


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
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
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
