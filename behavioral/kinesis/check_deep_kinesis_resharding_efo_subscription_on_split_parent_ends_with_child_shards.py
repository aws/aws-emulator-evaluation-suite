"""deep-kinesis-resharding-efo-subscription-on-split-parent-ends-with-child-shards."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-kinesis-resharding-efo-subscription-on-split-parent-ends-with-child-shards"
GROUP = 'resharding'
SERVICES = ['kinesis']

MAX_HASH = 2 ** 128 - 1


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _md5(key: str) -> int:
    return int(hashlib.md5(key.encode()).hexdigest(), 16)


def _range(shard: dict) -> tuple[int, int]:
    return (int(shard["HashKeyRange"]["StartingHashKey"]),
            int(shard["HashKeyRange"]["EndingHashKey"]))


def _is_open(shard: dict) -> bool:
    return "EndingSequenceNumber" not in shard["SequenceNumberRange"]


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    """Delete the stream at teardown and prove it is gone.

    DeleteStream is refused with ResourceInUseException while the stream is UPDATING.
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
        raise AssertionError(f"stream {name} still describable {timeout_s}s after DeleteStream")

    ctx.on_cleanup(_teardown)


def _await_ready(c, name, timeout_s=240):
    """Wait until ACTIVE per DescribeStreamSummary AND listable: the summary flips first."""
    def probe():
        s = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if s["StreamStatus"] != "ACTIVE":
            return s["StreamStatus"]
        try:
            c.list_shards(StreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
                return "ACTIVE-but-unlistable"
            raise
        return "READY"
    _poll(probe, lambda st: st == "READY", timeout_s, 2, f"stream {name} ACTIVE and listable")


def _await_topology(c, name, pred, description, timeout_s=240):
    """Poll until the stream is ready AND its shard map satisfies ``pred``; return the map.

    The summary can still read ACTIVE right after a reshard call, before the stream is UPDATING.
    """
    def probe():
        _await_ready(c, name, timeout_s)
        return _list_shards(c, name)
    return _poll(probe, pred, timeout_s, 2, description)


def _create_stream(ctx, c, shard_count):
    name = ctx.unique_name("sim2real-behav-kre-")
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, ShardCount=shard_count,
                            StreamModeDetails={"StreamMode": "PROVISIONED"},
                            Tags={"sim2real": "deep-kinesis-resharding"})
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            time.sleep(min(5 + attempt * 2, 15))
    else:
        raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}")
    _register_stream_teardown(ctx, c, name)
    _await_ready(c, name)
    return name


def _list_shards(c, name):
    out, token = [], None
    while True:
        resp = c.list_shards(**({"NextToken": token} if token else {"StreamName": name}))
        out += resp["Shards"]
        token = resp.get("NextToken")
        if not token:
            return out


def _drain_closed(c, name, shard_id, max_pages=400):
    """Read a CLOSED shard to its end: the page with no NextShardIterator. Returns (records, final)."""
    it = c.get_shard_iterator(StreamName=name, ShardId=shard_id,
                              ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records = []
    for _ in range(max_pages):
        resp = c.get_records(ShardIterator=it, Limit=1000)
        records += resp["Records"]
        it = resp.get("NextShardIterator")
        if it is None:
            return records, resp
        time.sleep(0.25)
    raise AssertionError(f"closed shard {shard_id} never returned a null NextShardIterator "
                         f"in {max_pages} pages; read {len(records)} records")


def _drain_open(c, name, shard_id, want, timeout_s=120):
    """Read an OPEN shard until ``want`` records are in hand and a caught-up empty page follows."""
    it = c.get_shard_iterator(StreamName=name, ShardId=shard_id,
                              ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = c.get_records(ShardIterator=it, Limit=1000)
        records += resp["Records"]
        it = resp["NextShardIterator"]
        if (len(records) >= want and not resp["Records"]
                and resp.get("MillisBehindLatest", 1) == 0):
            return records
        time.sleep(0.5)
    raise AssertionError(f"open shard {shard_id} served {len(records)} of {want} expected "
                         f"records within {timeout_s}s")


def _put_until_open(c, name, key, closed_ids, tag, writes, timeout_s=180):
    """PutRecord ``key`` until the service routes it to an OPEN shard; log every write.

    Routing leaves a split parent ~20 s after the stream is ACTIVE; earlier writes land in the parent.
    """
    deadline = time.monotonic() + timeout_s
    n = 0
    while True:
        data = f"{tag}-{n}"
        resp = c.put_record(StreamName=name, PartitionKey=key, Data=data.encode())
        writes.append((key, data, resp["ShardId"]))
        if resp["ShardId"] not in closed_ids:
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(f"PutRecord({key!r}) was still routed to closed shard "
                                 f"{resp['ShardId']} {timeout_s}s after the reshard landed")
        n += 1
        time.sleep(1)


def _register_consumer(ctx, c, stream_arn, consumer_name):
    """Register an EFO consumer; deregistration is registered BEFORE waiting for ACTIVE."""
    resp = c.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)

    def _teardown():
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                c.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
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
        raise AssertionError(f"EFO consumer {consumer_name} still describable after deregistration")

    ctx.on_cleanup(_teardown)
    _poll(lambda: c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
          ["ConsumerDescription"]["ConsumerStatus"], lambda st: st == "ACTIVE", 180, 2,
          f"consumer {consumer_name} ACTIVE")
    return resp["Consumer"]["ConsumerARN"]


def _subscribe(c, arn, shard_id, stop, timeout_s=120, max_events=150):
    """Read SubscribeToShardEvents from TRIM_HORIZON until ``stop(payloads, event)`` is true.

    Kinesis pushes an event about once a second even when idle, so iteration is paced; the loop
    is bounded by an event count and a deadline so a silent target cannot hang the check. The
    event stream is always closed: an abandoned subscription holds the consumer-shard slot.
    """
    sub = c.subscribe_to_shard(ConsumerARN=arn, ShardId=shard_id,
                               StartingPosition={"Type": "TRIM_HORIZON"})
    stream = sub["EventStream"]
    payloads, events = [], []
    deadline = time.monotonic() + timeout_s
    try:
        for event in stream:
            ev = event.get("SubscribeToShardEvent")
            assert ev is not None, f"expected a SubscribeToShardEvent, got keys {sorted(event)}: {event!r}"
            events.append(ev)
            payloads += [bytes(r["Data"]).decode() for r in ev.get("Records", [])]
            if stop(payloads, ev):
                return payloads, events
            if len(events) >= max_events or time.monotonic() >= deadline:
                break
    finally:
        stream.close()
    raise AssertionError(
        f"subscription to {shard_id} ended its read budget ({len(events)} events / {timeout_s}s) "
        f"without the expected condition; payloads {payloads!r}; last event "
        f"{ {k: v for k, v in (events[-1] if events else {}).items() if k != 'Records'}!r}"
    )


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EFO subscription to a split parent delivers its records in order, then ChildShards.

    The ChildShards event names both children consistently with ListShards, and a subscription to
    a child carries only that child's records.
    """
    c = ctx.client("kinesis")
    name = _create_stream(ctx, c, 1)
    parent = _list_shards(c, name)[0]["ShardId"]
    stream_arn = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    arn = _register_consumer(ctx, c, stream_arn, ctx.unique_name("sim2real-behav-kre-efo-"))

    key = f"{name}-k"
    writes: list[tuple[str, str, str]] = []
    for tag in ("m", "c", "z", "a", "q"):
        data = f"pre-{tag}"
        resp = c.put_record(StreamName=name, PartitionKey=key, Data=data.encode())
        writes.append((key, data, resp["ShardId"]))
    assert all(s == parent for _k, _d, s in writes), f"setup: pre-split writes left the parent: {writes!r}"

    c.split_shard(StreamName=name, ShardToSplit=parent, NewStartingHashKey=str(2 ** 127))
    _await_topology(c, name, lambda sh: sum(1 for s in sh if s.get("ParentShardId") == parent) == 2,
                    f"the split of {parent} visible in ListShards")
    shards = {s["ShardId"]: s for s in _list_shards(c, name)}
    kids = sorted(i for i, s in shards.items() if s.get("ParentShardId") == parent)
    assert len(kids) == 2, f"split produced children {kids!r}"

    landed = _put_until_open(c, name, key, {parent}, "post", writes)
    child = landed["ShardId"]
    in_parent = [d for _k, d, s in writes if s == parent]
    in_child = [d for _k, d, s in writes if s == child]
    assert in_child, f"setup: no record was routed to a child: {writes!r}"

    payloads, events = _subscribe(c, arn, parent, lambda p, ev: bool(ev.get("ChildShards")))
    final = events[-1]
    assert payloads == in_parent, (
        f"the parent subscription delivered {payloads!r}; PutRecord attributed {in_parent!r} to "
        f"{parent}, in that order, and nothing else"
    )
    assert final.get("ContinuationSequenceNumber") is None, (
        f"the terminal event still carries ContinuationSequenceNumber "
        f"{final.get('ContinuationSequenceNumber')!r}; a closed shard's end has nowhere to continue"
    )
    named = sorted(cs["ShardId"] for cs in final["ChildShards"])
    assert named == kids, f"terminal event names ChildShards {named!r}, expected {kids!r}"
    for cs in final["ChildShards"]:
        assert cs["ParentShards"] == [parent], (
            f"ChildShards entry {cs['ShardId']} lists ParentShards {cs['ParentShards']!r}, expected [{parent!r}]"
        )
        assert cs["HashKeyRange"] == shards[cs["ShardId"]]["HashKeyRange"], (
            f"ChildShards entry {cs['ShardId']} range {cs['HashKeyRange']!r} disagrees with "
            f"ListShards {shards[cs['ShardId']]['HashKeyRange']!r}"
        )
    assert all(not ev.get("ChildShards") for ev in events[:-1]), (
        "ChildShards appeared on an event before the parent's last record was delivered"
    )

    got, _ev = _subscribe(c, arn, child, lambda p, ev: len(p) >= len(in_child))
    assert got == in_child, (
        f"the child subscription on {child} delivered {got!r}, expected exactly {in_child!r}"
    )
    assert not set(got) & set(in_parent), (
        f"the child subscription re-delivered parent records {sorted(set(got) & set(in_parent))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
