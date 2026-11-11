"""get-records-exceeding-the-per-shard-rate-throttles-then-recovers."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-records-exceeding-the-per-shard-rate-throttles-then-recovers"
GROUP = "data-plane"
SERVICES = ["kinesis"]

# GetRecords is limited to 5 transactions per second per shard. A sequential loop is paced below
# that ceiling by its own network round trip, so the burst is CONCURRENT, and it uses a client with
# ``config=Config(retries={"max_attempts": 1})``: "standard" retry mode treats
# ProvisionedThroughputExceededException as a throttling error and retries it transparently, so a
# throttled call would otherwise come back late, never as a ``ClientError``.
#
# What the check asserts:
#   - The code is ProvisionedThroughputExceededException, matching the API reference's "five
#     transactions per second per shard".
#   - A throttled call returns no data and does not move the read position: every concurrent
#     success reuses one iterator and all of them carry the identical sequence numbers.
#   - The limiter refills within _RECOVERY_DEADLINE_S (30 s).
#   - AWS accepts a burst of calls before the first refusal. The refusals come sub-second, so
#     dividing by elapsed time mostly measures scheduler/network jitter; the COUNT is the stable
#     observable: it is a burst credit, not a per-second rate. _MAX_ACCEPTED_BEFORE_THROTTLE below
#     bounds that count instead.

_N_RECORDS = 3
_PAYLOADS = tuple(f"throttle-probe-{i}".encode() for i in range(_N_RECORDS))
_PARTITION_KEY = "throttle-pk"

#: Documented, non-adjustable API constant: GetRecords is 5 transactions per second per shard.
_DOCUMENTED_TPS_PER_SHARD = 5
#: AWS allows a burst credit of about 19 concurrent calls before refusing, well above the
#: documented rate; this allows roughly 2x that burst credit so a genuine limiter isn't failed for account-to-account
#: variance, while a target with no limiter at all (which runs on to _MAX_BURST, hundreds/s) still is.
_MAX_ACCEPTED_BEFORE_THROTTLE = 40
#: Concurrent in-flight GetRecords calls per batch — well above the 5 TPS/shard ceiling so a batch
#: lands inside one second and cannot be paced away by round-trip latency the way a sequential loop is.
_CONCURRENCY = 10
#: Upper bound on total successful calls issued before giving up on tripping the limiter.
_MAX_BURST = 120
#: Upper bound on how long the burst may run before the limiter must have bitten.
_BURST_DEADLINE_S = 20.0
_RECOVERY_DEADLINE_S = 30.0


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetRecords is rate limited per shard: an unpaced burst is refused with
    ProvisionedThroughputExceededException without returning data or moving the read position, and
    the identical call succeeds again once the limiter refills."""
    kinesis = ctx.client("kinesis")
    # The base client retries a throttled call transparently (see the measurement note above); the
    # burst and recovery legs need the RAW per-call outcome, so they use a client with retries off.
    kinesis_noretry = ctx.client("kinesis", config=Config(retries={"max_attempts": 1}))
    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])

    put_seqs = [
        kinesis.put_record(
            StreamName=stream["name"], Data=payload, PartitionKey=_PARTITION_KEY
        )["SequenceNumber"]
        for payload in _PAYLOADS
    ]

    iterator = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    # ---- Positive control: one paced call on this exact wiring succeeds ----
    control = _poll_until(
        lambda: kinesis.get_records(ShardIterator=iterator, Limit=1000),
        lambda r: len(r["Records"]) >= _N_RECORDS,
        timeout_s=60.0,
        interval_s=1.0,
        description=f"all {_N_RECORDS} records to be readable from {shard_id} at a paced rate",
    )
    expected_seqs = [r["SequenceNumber"] for r in control["Records"]]
    assert expected_seqs == put_seqs, (
        f"positive control: GetRecords returned {expected_seqs}; expected {put_seqs}"
    )

    # ---- Break exactly one thing: the CALL RATE. Same iterator, so nothing else changes ----
    # Issued CONCURRENTLY (see the measurement note above): a sequential unpaced loop is paced by
    # its own round-trip latency to within noise of 5 TPS and never accumulates a burst.
    def _burst_call() -> tuple[str, object]:
        try:
            resp = kinesis_noretry.get_records(ShardIterator=iterator, Limit=1000)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "ProvisionedThroughputExceededException":
                return "throttled", error
            raise
        return "ok", [r["SequenceNumber"] for r in resp["Records"]]

    throttle_error: dict | None = None
    successes = 0
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        while (
            throttle_error is None
            and successes < _MAX_BURST
            and time.monotonic() - started <= _BURST_DEADLINE_S
        ):
            batch_size = min(_CONCURRENCY, _MAX_BURST - successes)
            futures = [pool.submit(_burst_call) for _ in range(batch_size)]
            for future in as_completed(futures):
                kind, payload = future.result()
                if kind == "throttled":
                    throttle_error = throttle_error or payload
                    continue
                successes += 1
                # Freeze detector: the position never moved, so every response must be identical.
                assert payload == expected_seqs, (
                    f"a concurrent burst call on the SAME iterator returned {payload}; expected the "
                    f"identical {expected_seqs} — repeated reads must not advance the shard"
                )
    burst_elapsed = max(time.monotonic() - started, 1e-6)

    assert throttle_error is not None, (
        f"{successes} concurrent GetRecords calls against ONE shard in {burst_elapsed:.2f}s were "
        f"all accepted; expected ProvisionedThroughputExceededException — GetRecords is documented "
        f"at {_DOCUMENTED_TPS_PER_SHARD} transactions per second per shard"
    )
    # The burst credit is measured, not documented: accepting no more than the documented rate
    # over the burst's own duration (plus one second's worth) also honours the limit.
    assert successes <= _MAX_ACCEPTED_BEFORE_THROTTLE or successes <= _DOCUMENTED_TPS_PER_SHARD * (
        burst_elapsed + 1
    ), (
        f"GetRecords accepted {successes} concurrent calls in {burst_elapsed:.2f}s before its first "
        f"refusal; real AWS's measured burst credit on one shard is ~19 calls and this check allows "
        f"up to {_MAX_ACCEPTED_BEFORE_THROTTLE} for account-to-account variance — a target that "
        "accepts substantially more before ever refusing is not enforcing anything close to the "
        f"documented {_DOCUMENTED_TPS_PER_SHARD} transactions/s per shard"
    )

    # ---- The limiter refills, and the IDENTICAL call succeeds again ----
    recovered = _poll_until(
        lambda: _get_records_or_none(kinesis_noretry, iterator),
        lambda r: r is not None,
        timeout_s=_RECOVERY_DEADLINE_S,
        interval_s=2.0,
        description=(
            f"the per-shard GetRecords limiter on {shard_id} to refill so the identical call "
            "succeeds again"
        ),
    )

    # ---- Effect absent: the throttled calls returned no data and moved nothing ----
    recovered_seqs = [r["SequenceNumber"] for r in recovered["Records"]]
    assert recovered_seqs == expected_seqs, (
        f"after recovering from the throttle, the same iterator returned {recovered_seqs}; expected "
        f"the identical {expected_seqs} — a throttled GetRecords returns no data and must not "
        "consume the position"
    )

    # ---- Terminal independent read: a fresh iterator still sees every record ----
    fresh = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    final = _poll_until(
        lambda: _get_records_or_none(kinesis, fresh),
        lambda r: r is not None and len(r["Records"]) >= _N_RECORDS,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"a fresh TRIM_HORIZON iterator on {shard_id} to return all {_N_RECORDS} records",
    )
    final_payloads = [r["Data"] for r in final["Records"]]
    assert final_payloads == list(_PAYLOADS), (
        f"a fresh TRIM_HORIZON read after the throttle storm returned {final_payloads!r}; expected "
        f"{list(_PAYLOADS)!r} — throttling must not lose or reorder records"
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


def _get_records_or_none(kinesis, iterator: str) -> dict | None:
    """The response, or None when the call is throttled. Any OTHER error propagates."""
    try:
        return kinesis.get_records(ShardIterator=iterator, Limit=1000)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ProvisionedThroughputExceededException":
            return None
        raise


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
