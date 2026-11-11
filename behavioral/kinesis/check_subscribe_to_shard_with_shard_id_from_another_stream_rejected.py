"""subscribe-to-shard-with-shard-id-from-another-stream-rejected."""
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
    deregistration is registered before the wait for ACTIVE: a consumer stuck in CREATING still
    bills, and cleanup must not depend on this check reaching its assertions.
    """
    resp = c.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)

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

    Kinesis pushes an event roughly once per second even when a shard is idle, so iteration is
    naturally paced rather than blocking; the loop is bounded by both an event count and a
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


def _subscribe_error(c, **kwargs):
    """Return the error (Code and Message) SubscribeToShard raised, or raise if it wrongly SUCCEEDED.

    The success path closes the event stream before failing: an abandoned HTTP/2 subscription
    holds the consumer's single slot on that shard for five minutes and keeps billing, so a check
    that asserts a refusal must not leak one when the refusal does not come. It returns no falsy
    sentinel on success either — an emulator accepting input real AWS rejects is the strongest
    signal available here and must not be reported as an error-code mismatch.
    """
    try:
        resp = c.subscribe_to_shard(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {})
    resp["EventStream"].close()
    raise AssertionError(
        f"SubscribeToShard returned 200 with a live event stream for ConsumerARN "
        f"{kwargs.get('ConsumerARN')!r} on ShardId {kwargs.get('ShardId')!r}; that shard id does "
        f"not exist in the stream the consumer is registered against, and real AWS refuses it"
    )


CHECK = "subscribe-to-shard-with-shard-id-from-another-stream-rejected"
GROUP = 'consumers'
SERVICES = ['kinesis']


@tags("axis:rejection", "concern:negative-classes", "dp:api", "plane:data", "cap:c2", "cap:c6")
def run(ctx) -> None:
    """SubscribeToShard resolves ShardId within the consumer's own stream.

    A shard id that exists only in another stream is refused with ResourceNotFoundException, the
    consumer is untouched, and the other stream's record is not delivered.
    """
    c = ctx.client("kinesis")
    payload_own = b"own-stream-record"
    payload_other = b"other-stream-record"
    expected_code = "ResourceNotFoundException"

    # Shard ids are numbered per stream, so both streams have shardId-000000000000; the other
    # stream's second shard id exists nowhere in the consumer's 1-shard stream.
    own = _provisioned_stream(ctx, c, shard_count=1)
    other = _provisioned_stream(ctx, c, shard_count=2)
    own_shards = [s["ShardId"] for s in _get_shards(c, own)]
    other_shards = sorted(
        _get_shards(c, other), key=lambda s: int(s["HashKeyRange"]["StartingHashKey"])
    )
    assert len(own_shards) == 1, (
        f"expected a 1-shard stream, {own!r} has {own_shards!r}"
    )
    foreign = [s for s in other_shards if s["ShardId"] not in own_shards]
    assert foreign, (
        f"setup invalid: every shard id of {other!r} "
        f"({[s['ShardId'] for s in other_shards]!r}) also exists in {own!r} ({own_shards!r}), so "
        f"there is no shard id that is foreign to the consumer's stream"
    )
    foreign_shard = foreign[0]

    own_arn = _stream_arn(c, own)
    consumer = ctx.unique_name("sim2real-behav-kds-consumer-")
    consumer_arn = _register_consumer(ctx, c, own_arn, consumer)
    _wait_consumer_active(c, own_arn, consumer)
    assert consumer_arn.startswith(own_arn + "/consumer/"), (
        f"setup invalid: the consumer ARN {consumer_arn!r} is not scoped under its stream's ARN "
        f"{own_arn!r}, so the lookup below would not be a cross-stream one"
    )

    resp = _call_when_ready(
        lambda: c.put_record(StreamName=own, Data=payload_own, PartitionKey="k")
    )
    assert resp["ShardId"] == own_shards[0], (
        f"the record for the consumer's own stream landed on {resp['ShardId']!r}, not its only "
        f"shard {own_shards[0]!r}"
    )
    resp = _call_when_ready(
        lambda: c.put_record(
            StreamName=other, Data=payload_other, PartitionKey="k",
            ExplicitHashKey=foreign_shard["HashKeyRange"]["StartingHashKey"],
        )
    )
    assert resp["ShardId"] == foreign_shard["ShardId"], (
        f"the other stream's record landed on {resp['ShardId']!r}, not the shard whose id is "
        f"foreign to the consumer's stream ({foreign_shard['ShardId']!r}); the isolation "
        f"assertion below would then have nothing to isolate"
    )

    # Positive control FIRST: the same consumer against a shard id its OWN stream has. It receives
    # its own stream's record and nothing from the other stream.
    control = c.subscribe_to_shard(
        ConsumerARN=consumer_arn, ShardId=own_shards[0],
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    control_stream = control["EventStream"]
    try:
        control_payloads, control_events = _read_events(control_stream, want_records=1)
    finally:
        control_stream.close()
    assert control_payloads == [payload_own], (
        f"positive control: subscribing to {own_shards[0]!r} with {consumer!r}, the consumer "
        f"registered on that stream, delivered {control_payloads!r} over "
        f"{len(control_events)} events, expected {[payload_own]!r}"
    )
    assert payload_other not in control_payloads, (
        f"the consumer's own shard delivered the OTHER stream's record {payload_other!r}: "
        f"{control_payloads!r}. Two streams that happen to share shard-id numbering are still two "
        f"streams"
    )

    # Break exactly one thing: the shard id, swapped for one that exists only in the other stream.
    error = _subscribe_error(
        c, ConsumerARN=consumer_arn, ShardId=foreign_shard["ShardId"],
        StartingPosition={"Type": "TRIM_HORIZON"},
    )
    code = error.get("Code")
    assert code == expected_code, (
        f"SubscribeToShard with ConsumerARN {consumer_arn!r} (registered on {own!r}, shards "
        f"{own_shards!r}) and ShardId {foreign_shard['ShardId']!r} (which exists only in "
        f"{other!r}) failed with {code!r}; real AWS answers {expected_code!r}. The same consumer "
        f"was accepted on {own_shards[0]!r} moments earlier, so this is the shard id and nothing "
        f"else"
    )
    want = f"Shard {foreign_shard['ShardId']} in stream {own} under account {ctx.account} does not exist"
    assert error.get("Message") == want, f"expected message {want!r}, got {error.get('Message')!r}"

    # Effect absent: the consumer is untouched...
    after = c.describe_stream_consumer(StreamARN=own_arn, ConsumerName=consumer)[
        "ConsumerDescription"
    ]
    assert after["ConsumerStatus"] == "ACTIVE", (
        f"the consumer {consumer!r} is {after['ConsumerStatus']!r} after being pointed at another "
        f"stream's shard id; a refused subscription must not disturb the consumer"
    )
    assert after["ConsumerARN"] == consumer_arn, (
        f"the consumer ARN changed from {consumer_arn!r} to {after['ConsumerARN']!r} across the "
        f"refused subscription"
    )

    # ...and the other stream's record is still sitting in the other stream, unread and unmoved.
    iterator = c.get_shard_iterator(
        StreamName=other, ShardId=foreign_shard["ShardId"],
        ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]
    records, _next_it, pages = _drain(c, iterator, want=1)
    assert [bytes(r["Data"]) for r in records] == [payload_other], (
        f"the other stream's shard {foreign_shard['ShardId']!r} now reads back "
        f"{[bytes(r['Data']) for r in records]!r} over {pages} pages, expected "
        f"{[payload_other]!r}; the refused subscription must consume nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
