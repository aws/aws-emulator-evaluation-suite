"""subscribe-to-shard-second-subscription-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError, EventStreamError


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
        Tags={"sim2real": CHECK},
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


def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]


def _wait_consumer_active(c, stream_arn, consumer_name, timeout_s=180, interval_s=2):
    return _poll(
        lambda: c.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )["ConsumerDescription"],
        lambda d: d["ConsumerStatus"] == "ACTIVE",
        timeout_s, interval_s, f"consumer {consumer_name} ACTIVE",
    )


def _register_consumer(ctx, c, stream_arn, consumer_name):
    """Register an enhanced-fan-out consumer, deregistering it at teardown.

    EFO is billed per consumer-shard-hour on top of the stream's shard-hours, so the
    deregistration is registered before the wait for ACTIVE: a consumer stuck in CREATING
    still bills, and cleanup must not depend on this check reaching its assertions.
    """
    resp = c.register_stream_consumer(
        StreamARN=stream_arn, ConsumerName=consumer_name, Tags={"sim2real": CHECK}
    )

    def _teardown():
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                c.deregister_stream_consumer(
                    StreamARN=stream_arn, ConsumerName=consumer_name
                )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException":
                    raise
                time.sleep(5)
                continue
            break
        while time.monotonic() < deadline:
            try:
                c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)
        raise AssertionError(
            f"EFO consumer {consumer_name} on {stream_arn} is still describable after "
            f"deregistration; it is still billing consumer-shard-hours"
        )

    ctx.on_cleanup(_teardown)
    return resp["Consumer"]["ConsumerARN"]


def _read_events(event_stream, want_records, timeout_s=90, max_events=90):
    """Read SubscribeToShardEvents until ``want_records`` records have arrived.

    Kinesis pushes an event roughly once per second even when a shard is idle, so iteration
    is naturally paced rather than blocking; the loop is bounded by both an event count and a
    wall-clock deadline so a silent emulator cannot hang the check.
    """
    deadline = time.monotonic() + timeout_s
    payloads = []
    events = []
    for event in event_stream:
        sub = event.get("SubscribeToShardEvent")
        assert sub is not None, (
            f"expected a SubscribeToShardEvent, got an event keyed {sorted(event)}: {event!r}"
        )
        events.append(sub)
        payloads.extend(bytes(r["Data"]) for r in sub.get("Records", []))
        if len(payloads) >= want_records:
            return payloads, events
        if len(events) >= max_events or time.monotonic() >= deadline:
            break
    raise AssertionError(
        f"SubscribeToShard delivered {len(payloads)} of {want_records} expected records over "
        f"{len(events)} events / {timeout_s}s: {payloads!r}"
    )


def _read_quietly(event_stream, seconds, max_events=90):
    """Read events for ``seconds``, asserting the stream does NOT fault. Returns the events.

    This is the control for the in-band failure below: a healthy subscription pushes events
    for up to five minutes without erroring, so if a subscription faults it is because of the
    conflict and not because of the act of reading.
    """
    deadline = time.monotonic() + seconds
    events = []
    payloads = []
    try:
        for event in event_stream:
            sub = event.get("SubscribeToShardEvent")
            assert sub is not None, (
                f"expected a SubscribeToShardEvent, got an event keyed {sorted(event)}: {event!r}"
            )
            events.append(sub)
            payloads.extend(bytes(r["Data"]) for r in sub.get("Records", []))
            if time.monotonic() >= deadline or len(events) >= max_events:
                return payloads, events
    except EventStreamError as exc:
        raise AssertionError(
            f"a SINGLE SubscribeToShard subscription faulted after {len(events)} events with "
            f"{exc.response.get('Error', {}).get('Code')!r}: {exc}. An uncontested subscription "
            f"must stream for its full lifetime; without this control the in-band conflict error "
            f"asserted later could not be attributed to the second subscription"
        ) from exc
    return payloads, events


def _read_until_fault(event_stream, timeout_s=60):
    """Read a subscription expecting it to be TERMINATED in band.

    Returns ``(code, message, payloads, events)``. Raises AssertionError if the stream instead
    keeps streaming or ends cleanly: the in-band error IS the observable, so its absence is a
    failure, not a pass.
    """
    deadline = time.monotonic() + timeout_s
    events = []
    payloads = []
    try:
        for event in event_stream:
            sub = event.get("SubscribeToShardEvent")
            if sub is not None:
                events.append(sub)
                payloads.extend(bytes(r["Data"]) for r in sub.get("Records", []))
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the subscription kept streaming for {timeout_s}s ({len(events)} events) "
                    f"without the in-band error that real AWS sends when a second subscription "
                    f"exists for the same consumer and shard"
                )
    except EventStreamError as exc:
        error = exc.response.get("Error", {}) if getattr(exc, "response", None) else {}
        return error.get("Code"), error.get("Message", str(exc)), payloads, events
    raise AssertionError(
        f"the subscription ended cleanly after {len(events)} events instead of faulting with the "
        f"in-band conflict error"
    )


CHECK = "subscribe-to-shard-second-subscription-rejected"
GROUP = 'consumers'
SERVICES = ['kinesis']


@tags("axis:rejection", "cap:c2", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second SubscribeToShard for a live consumer-shard pair is accepted with HTTP 200, then BOTH
    subscriptions are terminated in band by a ResourceInUseException event; a solo subscription
    streams without faulting, with ContinuationSequenceNumber and MillisBehindLatest set."""
    c = ctx.client("kinesis")
    payloads = [b"efo-alpha", b"efo-beta"]

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]
    stream_arn = _stream_arn(c, name)

    consumer_name = ctx.unique_name("sim2real-behav-kds-consumer-")
    consumer_arn = _register_consumer(ctx, c, stream_arn, consumer_name)
    desc = _wait_consumer_active(c, stream_arn, consumer_name)
    assert desc["ConsumerARN"] == consumer_arn, (
        f"DescribeStreamConsumer reports ConsumerARN {desc['ConsumerARN']}, but "
        f"RegisterStreamConsumer minted {consumer_arn}"
    )

    for payload in payloads:
        _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="k")
        )

    # --- Control leg: ONE subscription, uncontested. It delivers the records in produced order
    # with the resume and lag fields populated, and it does not fault while being read — which is
    # what makes the in-band fault in the conflict leg attributable to the conflict.
    solo = c.subscribe_to_shard(
        ConsumerARN=consumer_arn,
        ShardId=shard_id,
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    solo_stream = solo["EventStream"]
    try:
        got, events = _read_events(solo_stream, want_records=len(payloads))
        assert got == payloads, (
            f"the uncontested subscription delivered {got!r} over {len(events)} events; "
            f"enhanced fan-out preserves per-shard order, so it must be exactly {payloads!r}"
        )
        for i, ev in enumerate(events):
            cont = ev.get("ContinuationSequenceNumber")
            assert cont, (
                f"SubscribeToShardEvent {i} has ContinuationSequenceNumber={cont!r}; without "
                f"it a consumer cannot resume the subscription after a disconnect: {ev!r}"
            )
            lag = ev.get("MillisBehindLatest")
            assert isinstance(lag, int) and lag >= 0, (
                f"SubscribeToShardEvent {i} has MillisBehindLatest={lag!r}; it must be a "
                f"non-negative integer lag gauge"
            )
        quiet_payloads, quiet_events = _read_quietly(solo_stream, seconds=10)
        assert quiet_events, (
            "an uncontested subscription must keep pushing events (Kinesis emits one roughly "
            "every second even on an idle shard); none arrived in 10s"
        )
        assert quiet_payloads == [], (
            f"the shard holds only {payloads!r} and they were already delivered, so continued "
            f"reading must yield no further records; got {quiet_payloads!r} — records are being "
            f"re-delivered on a live subscription"
        )
    finally:
        solo_stream.close()

    # --- Break exactly one thing: a SECOND subscription for the same consumer and shard while
    # the first is still open, issued immediately so it lands inside the documented 5-second
    # window in which a repeat call is said to fail. The incumbent is opened with a bounded
    # retry rather than a fixed sleep: the closed solo subscription's slot does not necessarily
    # clear the instant EventStream.close() returns, and a fixed wait either races a slow clear
    # or wastes time on a fast one.
    first = _call_when_ready(
        lambda: c.subscribe_to_shard(
            ConsumerARN=consumer_arn,
            ShardId=shard_id,
            StartingPosition={"Type": "TRIM_HORIZON"},
        ),
        timeout_s=60,
    )
    started = time.monotonic()
    first_stream = first["EventStream"]
    second_stream = None
    try:
        try:
            second = c.subscribe_to_shard(
                ConsumerARN=consumer_arn,
                ShardId=shard_id,
                StartingPosition={"Type": "TRIM_HORIZON"},
            )
        except ClientError as exc:
            raise AssertionError(
                f"the second SubscribeToShard was refused at the HTTP layer with "
                f"{exc.response.get('Error', {}).get('Code')!r}. Real AWS ACCEPTS the call (200 "
                f"with a live event stream) and reports the conflict IN BAND on both event "
                f"streams instead; answering an HTTP error here is the shortcut this check "
                f"exists to catch"
            ) from exc
        elapsed = time.monotonic() - started
        second_stream = second["EventStream"]
        # elapsed-bound: a repeat SubscribeToShard conflicts only within the documented 5 s window.
        assert elapsed < 5.0, (
            f"inconclusive: the second SubscribeToShard was issued {elapsed:.1f}s after the "
            f"first, outside the 5-second window in which a repeat call is documented to "
            f"conflict. Re-run; if this recurs the harness is too slow between two adjacent "
            f"API calls"
        )

        # Both subscriptions must be terminated in band by the SAME error. Reading the
        # incumbent first is deliberate: it is the one an emulator is most likely to leave
        # streaming, having "given" the shard to the newcomer.
        expected = (
            f"Another active subscription exists for this consumer: "
            f"{ctx.account}:{name}:{shard_id}:{consumer_name}"
        )
        for label, stream in (("incumbent", first_stream), ("challenger", second_stream)):
            code, message, _got, evs = _read_until_fault(stream)
            assert code == "ResourceInUseException", (
                f"the {label} subscription was terminated with {code!r} after {len(evs)} "
                f"events; real AWS faults BOTH subscriptions with an in-band "
                f"ResourceInUseException when a second one exists for the same consumer and "
                f"shard. Message was: {message!r}"
            )
            assert message == expected, (
                f"the {label} fault must attribute itself to the duplicate subscription and "
                f"name the contested shard and consumer; expected {expected!r}, got {message!r}"
            )
    finally:
        first_stream.close()
        if second_stream is not None:
            second_stream.close()

    # Effect absent / recovery: with both faulted subscriptions closed, subscribing again works
    # and replays from TRIM_HORIZON, so the fault above was about concurrency and not a
    # permanently poisoned consumer or a consumed stream.
    deadline = time.monotonic() + 60
    last_code = None
    while True:
        try:
            resumed = c.subscribe_to_shard(
                ConsumerARN=consumer_arn,
                ShardId=shard_id,
                StartingPosition={"Type": "TRIM_HORIZON"},
            )
            break
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            assert last_code == "ResourceInUseException", (
                f"re-subscribing after closing the first stream failed with {last_code}"
            )
            assert time.monotonic() < deadline, (
                f"re-subscribing to shard {shard_id} as consumer {consumer_arn} kept failing "
                f"with {last_code} for 60s after the first subscription was closed; the "
                f"one-subscription slot is never released"
            )
            time.sleep(3)
    resumed_stream = resumed["EventStream"]
    try:
        got_again, _events = _read_events(resumed_stream, want_records=1, timeout_s=60)
        assert got_again[0] == payloads[0], (
            f"the re-subscription from TRIM_HORIZON delivered {got_again[0]!r} first, "
            f"expected the oldest record {payloads[0]!r}"
        )
    finally:
        resumed_stream.close()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
