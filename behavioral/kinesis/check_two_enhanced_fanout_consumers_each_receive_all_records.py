"""two-enhanced-fanout-consumers-each-receive-all-records."""
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

    DeleteStream is refused with ResourceInUseException while the stream is CREATING or UPDATING.
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

    Cleanup is registered before the wait for ACTIVE: a consumer stuck in CREATING still bills.
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

    Kinesis pushes an event roughly once per second even on an idle shard; the loop is bounded
    by an event count and a deadline so a silent stream cannot hang the check.
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


CHECK = "two-enhanced-fanout-consumers-each-receive-all-records"
GROUP = 'consumers'
SERVICES = ['kinesis']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c6",
)
def run(ctx) -> None:
    """Two enhanced-fan-out consumers each receive the shard's complete record set in order from
    TRIM_HORIZON: consumer 2 reads after consumer 1 drained, so one must not consume the other's
    records, and both stay ACTIVE afterwards.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/enhanced-consumers.html
    """
    c = ctx.client("kinesis")
    payloads = [f"efo-{t}".encode() for t in ("m", "c", "z", "a", "q")]
    assert payloads != sorted(payloads), (
        f"payload sequence {payloads!r} must not be sorted, or a sorting emulator passes"
    )

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]
    stream_arn = _stream_arn(c, name)

    # Register both consumers before waiting on either: they reach ACTIVE in parallel.
    names = [ctx.unique_name(f"sim2real-behav-kds-consumer-{i}-") for i in (1, 2)]
    arns = [_register_consumer(ctx, c, stream_arn, n) for n in names]
    descs = [_wait_consumer_active(c, stream_arn, n) for n in names]

    assert arns[0] != arns[1], (
        f"both registrations returned the same ConsumerARN {arns[0]!r}, so the check cannot prove "
        f"independence"
    )
    for i, desc in enumerate(descs):
        assert desc["ConsumerARN"] == arns[i], (
            f"DescribeStreamConsumer reports ConsumerARN {desc['ConsumerARN']!r} for "
            f"{names[i]!r}, but RegisterStreamConsumer minted {arns[i]!r}"
        )

    for i, payload in enumerate(payloads):
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="same-key")
        )
        assert resp["ShardId"] == shard_id, (
            f"record {i} ({payload!r}) landed on {resp['ShardId']!r}, not the only shard "
            f"{shard_id!r}"
        )

    # Sequential on purpose: the check is about independence, not timing. Streams are closed in
    # finally because an abandoned HTTP/2 subscription holds its slot for five minutes.
    received = []
    for i, arn in enumerate(arns):
        sub = c.subscribe_to_shard(
            ConsumerARN=arn, ShardId=shard_id, StartingPosition={"Type": "TRIM_HORIZON"},
        )
        stream = sub["EventStream"]
        try:
            got, events = _read_events(stream, want_records=len(payloads))
        finally:
            stream.close()
        received.append(got)
        assert got == payloads, (
            f"consumer {i + 1} ({names[i]!r}) received {got!r} over {len(events)} events; "
            f"enhanced fan-out delivers each consumer the shard's whole contents in per-shard "
            f"order, so it must be exactly {payloads!r}"
        )

    assert received[0] == received[1], (
        f"consumer 1 received {received[0]!r} and consumer 2 received {received[1]!r}. Two "
        f"enhanced-fan-out consumers read the same shard independently: neither consumes the "
        f"other's records, so the two deliveries must be identical"
    )

    for i, n in enumerate(names):
        after = c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=n)[
            "ConsumerDescription"
        ]
        assert after["ConsumerStatus"] == "ACTIVE", (
            f"consumer {i + 1} ({n!r}) is {after['ConsumerStatus']!r} after its subscription was "
            f"read and closed; reading a subscription must not consume the consumer"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
