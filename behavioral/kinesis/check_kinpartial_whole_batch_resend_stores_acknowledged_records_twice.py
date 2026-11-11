"""kinpartial-whole-batch-resend-stores-acknowledged-records-twice."""
from __future__ import annotations

import collections
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

# A shard's write quota is reported PER ENTRY, so this is the one code a partially-failed entry
# carries.
THROTTLE = "ProvisionedThroughputExceededException"


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _summary_status(c, name):
    """The stream's status, or None when the control plane throttled the question."""
    try:
        return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "LimitExceededException":
            return None
        raise


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags={"sim2real": "kinesis-partial-failure"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _register_stream_teardown(ctx, c, name, timeout_s=240, interval_s=5):
    """Delete the stream at teardown and prove it is gone.

    DeleteStream is refused with ResourceInUseException while the stream is CREATING.
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


def _wait_stream_active(c, name, timeout_s=240, interval_s=2):
    _poll(
        lambda: _summary_status(c, name),
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=240):
    """Wait for ACTIVE, then for ListShards: it answers ResourceInUseException for a few seconds
    after DescribeStreamSummary already reports ACTIVE."""
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
    # PROVISIONED with ShardCount=1 is the cheapest ACTIVE stream, and a single shard is what makes
    # the shard's own write quota reachable at all.
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


def _tag_of(data):
    """The unique tag a padded record carries in front of its padding."""
    return bytes(data).split(b".", 1)[0]


def _entries(prefix, count, size, partition_keys):
    """``count`` PutRecords entries of ``size`` bytes, each uniquely tagged, keys round-robined."""
    out = []
    for i in range(count):
        tag = f"{prefix}-{i}".encode()
        out.append({
            "Data": tag + b"." + b"p" * (size - len(tag) - 1),
            "PartitionKey": partition_keys[i % len(partition_keys)],
        })
    return out


def _marker(c, name, timeout_s=120, interval_s=1.0):
    """Write one marker record and return its SequenceNumber, to bound a read window below.

    A call-level throttle stores nothing, so retrying on exactly that code cannot duplicate a record.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return c.put_record(
                StreamName=name, Data=b"marker." + b"m" * 8, PartitionKey="pk-marker"
            )["SequenceNumber"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != THROTTLE or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _provoke_partial_batch(c, name, entries_for, max_attempts=60):
    """Send back-to-back PutRecords calls until one comes back partially failed.

    Returns ``(marker_sequence_number, entries, response)``; the shard's burst allowance means
    the opening calls are fully accepted, and a wholly rejected call is skipped.
    """
    sent = 0
    whole_call_rejections = 0
    for attempt in range(max_attempts):
        marker = _marker(c, name)
        entries = entries_for(attempt)
        try:
            resp = _call_when_ready(lambda e=entries: c.put_records(StreamName=name, Records=e))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != THROTTLE:
                raise
            whole_call_rejections += 1
            continue
        sent += len(entries)
        failed = resp["FailedRecordCount"]
        if 0 < failed < len(entries):
            return marker, entries, resp
    raise AssertionError(
        f"{max_attempts} back-to-back PutRecords calls ({sent} records accepted-or-reported, "
        f"{whole_call_rejections} rejected whole) to a ONE-shard stream never produced a PARTIAL "
        f"outcome: every call was either wholly accepted or wholly refused. A shard reports its "
        f"write quota PER ENTRY, so overshooting it inside one call must split the batch"
    )


def _window_to_tip(c, name, shard_id, after_seq, want, timeout_s=180, interval_s=1.0):
    """Every record the shard holds after ``after_seq``, read until MillisBehindLatest == 0.

    An empty page alone is not terminal: GetRecords can return one before a write is visible.
    """
    it = _call_when_ready(lambda: c.get_shard_iterator(
        StreamName=name, ShardId=shard_id,
        ShardIteratorType="AFTER_SEQUENCE_NUMBER", StartingSequenceNumber=after_seq,
    )["ShardIterator"])
    records = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = c.get_records(ShardIterator=it, Limit=10000)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != THROTTLE or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)
            continue
        pages += 1
        records.extend(resp.get("Records", []))
        at_tip = resp.get("MillisBehindLatest") == 0
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return records, pages
        it = nxt
        if len(records) >= want and at_tip:
            return records, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"read {pages} GetRecords pages over {timeout_s}s and saw {len(records)} of "
                f"{want} expected records, MillisBehindLatest="
                f"{resp.get('MillisBehindLatest')!r}: {[_tag_of(r['Data']) for r in records][:8]!r}"
            )
        time.sleep(interval_s)


def _resend_until_acknowledged(c, name, entries, chunk_size=200, max_rounds=40, pace_s=1.0):
    """Resend ``entries``, retrying only those whose result carried an ErrorCode.

    Returns ``[(tag, sequence_number), ...]``; a raising call is not retried because its outcome is
    unknown and a retry could duplicate a record.
    """
    acks = []
    pending = list(entries)
    for _round in range(max_rounds):
        if not pending:
            return acks
        chunk, pending = pending[:chunk_size], pending[chunk_size:]
        resp = c.put_records(StreamName=name, Records=chunk)
        for i, r in enumerate(resp["Records"]):
            if r.get("ErrorCode"):
                pending.append(chunk[i])
            else:
                acks.append((_tag_of(chunk[i]["Data"]), r["SequenceNumber"]))
        time.sleep(pace_s)
    raise AssertionError(
        f"{len(pending)} of {len(entries)} resent entries were still unacknowledged after "
        f"{max_rounds} bounded rounds of {chunk_size}: {[_tag_of(e['Data']) for e in pending][:8]!r}"
    )


CHECK = "kinpartial-whole-batch-resend-stores-acknowledged-records-twice"
GROUP = "data-plane"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """Resending the whole batch after a partial failure stores every acknowledged payload twice
    (Kinesis does not deduplicate) and each refused payload once, at distinct sequence numbers.
    """
    # Retries are disabled deliberately: botocore's default would re-issue a PutRecords call whose
    # 200 was lost, silently adding the very duplicate this file counts.
    c = ctx.client("kinesis", config=Config(retries={"max_attempts": 1, "mode": "standard"}))
    batch_size = 500
    record_size = 200

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Positive control: an all-valid batch is wholly accepted and each payload lands exactly once.
    control_start = _marker(c, name)
    control_entries = _entries("ctl", 3, 64, ["pk-ctl"])
    control = _call_when_ready(lambda: c.put_records(StreamName=name, Records=control_entries))
    assert control["FailedRecordCount"] == 0, (
        f"the all-valid 3-record control batch reported FailedRecordCount "
        f"{control['FailedRecordCount']!r}: {control['Records']!r}"
    )
    control_window, _pages = _window_to_tip(c, name, shard_id, control_start, want=3)
    assert collections.Counter(_tag_of(r["Data"]) for r in control_window) == collections.Counter(
        _tag_of(e["Data"]) for e in control_entries
    ), (
        f"the control batch's 3 payloads read back as "
        f"{sorted(collections.Counter(_tag_of(r['Data']) for r in control_window).items())!r}; one "
        f"acknowledgement is one record, so each must be present exactly once"
    )

    marker, entries, resp = _provoke_partial_batch(
        c, name, lambda attempt: _entries(f"a{attempt}", batch_size, record_size, ["pk-bulk"])
    )
    results = resp["Records"]
    failed_idx = [i for i, r in enumerate(results) if r.get("ErrorCode")]
    ok_idx = [i for i, r in enumerate(results) if not r.get("ErrorCode")]
    codes = {results[i]["ErrorCode"] for i in failed_idx}
    assert codes == {THROTTLE}, (
        f"the refused entries carry error codes {sorted(codes)!r}; overshooting a shard's write "
        f"quota is reported per entry as exactly {THROTTLE!r}"
    )
    messages = {results[i].get("ErrorMessage") for i in failed_idx}
    want_message = f"Rate exceeded for shard {shard_id} in stream {name} under account {ctx.account}."
    assert messages == {want_message}, (
        f"the refused entries carry error messages {messages!r}; expected only {want_message!r}"
    )
    ok_tags = [_tag_of(entries[i]["Data"]) for i in ok_idx]
    failed_tags = [_tag_of(entries[i]["Data"]) for i in failed_idx]

    before, _pages = _window_to_tip(c, name, shard_id, marker, want=len(ok_idx))
    seen_before = collections.Counter(_tag_of(r["Data"]) for r in before)
    assert seen_before == collections.Counter(ok_tags), (
        f"before the resend the shard holds {len(before)} records past the marker for "
        f"{len(ok_idx)} acknowledged and {len(failed_idx)} refused entries: refused payloads "
        f"present {sorted(set(failed_tags) & set(seen_before))[:5]!r}, acknowledged payloads "
        f"missing {sorted(set(ok_tags) - set(seen_before))[:5]!r}"
    )

    # The one thing broken: resend EVERY entry rather than only the refused ones — the naive
    # producer, and the reason the per-entry ErrorCode exists.
    acks = _resend_until_acknowledged(c, name, list(entries))
    ack_counts = collections.Counter(tag for tag, _seq in acks)
    assert ack_counts == collections.Counter(_tag_of(e["Data"]) for e in entries), (
        f"the whole-batch resend acknowledged {sum(ack_counts.values())} entries for "
        f"{len(entries)} submitted; payloads acknowledged more than once in the resend leg "
        f"{[t for t, n in ack_counts.items() if n > 1][:5]!r}"
    )

    after, _pages = _window_to_tip(
        c, name, shard_id, marker, want=2 * len(ok_idx) + len(failed_idx)
    )
    seen_after = collections.Counter(_tag_of(r["Data"]) for r in after)
    expected = collections.Counter(ok_tags + ok_tags + failed_tags)
    assert seen_after == expected, (
        f"after resending all {len(entries)} entries the shard holds {len(after)} records past the "
        f"marker where {2 * len(ok_idx) + len(failed_idx)} are owed (each of the {len(ok_idx)} "
        f"acknowledged payloads twice, each of the {len(failed_idx)} refused payloads once). "
        f"Payloads at the wrong count: "
        f"{[(t, seen_after.get(t, 0), n) for t, n in expected.items() if seen_after.get(t, 0) != n][:5]!r}. "
        f"A count of 1 for a payload acknowledged twice means the service deduplicated a resent "
        f"record, which real Kinesis does not do"
    )

    positions = collections.defaultdict(list)
    for r in after:
        positions[_tag_of(r["Data"])].append(r["SequenceNumber"])
    collapsed = sorted(t for t, seqs in positions.items() if len(seqs) != len(set(seqs)))
    assert not collapsed, (
        f"{len(collapsed)} payloads are stored twice but share one SequenceNumber: "
        f"{[(t, positions[t]) for t in collapsed[:5]]!r}. A sequence number is a position within "
        f"the shard, so two records cannot occupy one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
