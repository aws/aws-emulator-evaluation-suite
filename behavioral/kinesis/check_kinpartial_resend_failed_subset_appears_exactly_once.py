"""kinpartial-resend-failed-subset-appears-exactly-once."""
from __future__ import annotations

import collections
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

# A shard's write quota is reported PER ENTRY, so this is the one code a partially-failed entry
# carries. It is provoked deliberately by this check, never inherited from account state.
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
    DeleteStream is refused while the stream is CREATING, so a bare delete would leak the stream."""

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
    """ACTIVE is not enough: ListShards answers ResourceInUseException/CREATING for a few seconds
    after DescribeStreamSummary already reports ACTIVE, so the shard is polled for separately."""
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
    """``count`` PutRecords entries of ``size`` bytes, each uniquely tagged, keys round-robined.
    The index is not zero-padded, so byte order differs from submission order (9 -> 10)."""
    out = []
    for i in range(count):
        tag = f"{prefix}-{i}".encode()
        out.append({
            "Data": tag + b"." + b"p" * (size - len(tag) - 1),
            "PartitionKey": partition_keys[i % len(partition_keys)],
        })
    return out


def _marker(c, name, timeout_s=120, interval_s=1.0):
    """Write one marker record and return its SequenceNumber, to bound a read window BELOW.
    A call-level throttle stores nothing, so re-issuing this call on that code cannot duplicate."""
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
    """Send back-to-back PutRecords calls until ONE comes back PARTIALLY failed.
    The shard's burst allowance accepts the opening calls; a wholly rejected call is skipped.
    Returns ``(marker_sequence_number, entries, response)`` for the partial call."""
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
    """Every record the shard holds AFTER ``after_seq``, read until MillisBehindLatest == 0.
    An empty page alone is not terminal: GetRecords can return one before a write is visible."""
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
    """Resend ``entries``, retrying ONLY the entries whose own result carried an ErrorCode.
    A call that RAISES is fatal, not retried: re-issuing it could duplicate a stored record.
    Returns the acknowledgement order as ``[(tag, sequence_number), ...]``."""
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


CHECK = "kinpartial-resend-failed-subset-appears-exactly-once"
GROUP = "data-plane"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """Resending only the entries PutRecords reported failed leaves every payload of the batch on
    the shard exactly once, counted per record rather than by set containment.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html
    """
    # Retries are disabled deliberately: botocore's default would re-issue a PutRecords call whose
    # 200 was lost, silently duplicating records — which would make this file's own subject
    # unobservable. A throttle must surface to the check, not be smoothed away under it.
    c = ctx.client("kinesis", config=Config(retries={"max_attempts": 1, "mode": "standard"}))
    batch_size = 500          # the per-call entry maximum: the widest batch a producer can split.
    record_size = 200

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Positive control, established FIRST and read back: a small all-valid batch is wholly
    # accepted, every entry carries a SequenceNumber and none carries an ErrorCode, and all three
    # payloads are on the shard exactly once. Everything below differs from this only in volume.
    control_start = _marker(c, name)
    control_entries = _entries("ctl", 3, 64, ["pk-ctl"])
    control = _call_when_ready(lambda: c.put_records(StreamName=name, Records=control_entries))
    assert control["FailedRecordCount"] == 0, (
        f"the all-valid 3-record control batch reported FailedRecordCount "
        f"{control['FailedRecordCount']!r}: {control['Records']!r}"
    )
    for i, r in enumerate(control["Records"]):
        assert r.get("SequenceNumber") and not r.get("ErrorCode"), (
            f"control entry {i} is {r!r}; a successful entry carries SequenceNumber + ShardId and "
            f"no ErrorCode"
        )
    control_window, _pages = _window_to_tip(c, name, shard_id, control_start, want=3)
    control_seen = collections.Counter(_tag_of(r["Data"]) for r in control_window)
    assert control_seen == collections.Counter(_tag_of(e["Data"]) for e in control_entries), (
        f"the control batch's 3 payloads read back from the shard as {dict(control_seen)!r}; an "
        f"accepted entry is stored exactly once, so the positive control must be 1 each"
    )

    # Break exactly one thing: the submission rate into a single shard. Everything else about the
    # batch stays valid.
    marker, entries, resp = _provoke_partial_batch(
        c, name, lambda attempt: _entries(f"a{attempt}", batch_size, record_size, ["pk-bulk"])
    )
    results = resp["Records"]
    assert len(results) == len(entries), (
        f"PutRecords returned {len(results)} result entries for {len(entries)} request entries; "
        f"Records[] is positionally aligned with the request and must never be compacted — a "
        f"producer resends by index"
    )
    failed_idx = [i for i, r in enumerate(results) if r.get("ErrorCode")]
    ok_idx = [i for i, r in enumerate(results) if not r.get("ErrorCode")]
    codes = {results[i]["ErrorCode"] for i in failed_idx}
    assert codes == {THROTTLE}, (
        f"the failed entries carry error codes {sorted(codes)!r}; overshooting a shard's write "
        f"quota is reported per entry as exactly {THROTTLE!r}"
    )
    messages = {results[i].get("ErrorMessage") for i in failed_idx}
    want_message = f"Rate exceeded for shard {shard_id} in stream {name} under account {ctx.account}."
    assert messages == {want_message}, (
        f"the refused entries carry error messages {messages!r}; expected only {want_message!r}"
    )
    ok_tags = [_tag_of(entries[i]["Data"]) for i in ok_idx]
    failed_tags = [_tag_of(entries[i]["Data"]) for i in failed_idx]

    # Effect absent, BEFORE any resend: the window holds exactly the acknowledged payloads, each
    # once, and none of the refused ones. This is what makes the resend below safe, and it is what
    # distinguishes a real partial failure from a silent success wearing an ErrorCode.
    before, _pages = _window_to_tip(c, name, shard_id, marker, want=len(ok_idx))
    seen_before = collections.Counter(_tag_of(r["Data"]) for r in before)
    assert seen_before == collections.Counter(ok_tags), (
        f"the {len(ok_idx)} acknowledged and {len(failed_idx)} refused entries of one PutRecords "
        f"call read back as {len(before)} records; leaked refused payloads "
        f"{sorted(set(failed_tags) & set(seen_before))[:5]!r}, missing acknowledged payloads "
        f"{sorted(set(ok_tags) - set(seen_before))[:5]!r}, duplicated payloads "
        f"{[t for t, n in seen_before.items() if n > 1][:5]!r}"
    )

    # Recovery: resend ONLY the refused entries, which is what the per-entry ErrorCode exists for.
    acks = _resend_until_acknowledged(c, name, [entries[i] for i in failed_idx])
    ack_counts = collections.Counter(tag for tag, _seq in acks)
    assert ack_counts == collections.Counter(failed_tags), (
        f"the resend acknowledged {sum(ack_counts.values())} entries for {len(failed_tags)} "
        f"refused ones; payloads acknowledged more than once: "
        f"{[t for t, n in ack_counts.items() if n > 1][:5]!r}"
    )

    # The claim, per record: after the resend, each payload of the batch is on the shard exactly once.
    after, _pages = _window_to_tip(c, name, shard_id, marker, want=len(entries))
    seen_after = collections.Counter(_tag_of(r["Data"]) for r in after)
    duplicated = sorted(t for t, n in seen_after.items() if n > 1)
    assert not duplicated, (
        f"{len(duplicated)} payloads appear MORE THAN ONCE on the shard after only the refused "
        f"subset was resent: {[(t, seen_after[t]) for t in duplicated[:5]]!r}. Every one of them "
        f"was reported {THROTTLE!r} and was absent from the shard before the resend, so a second "
        f"copy means the service stored an entry it told the producer it had refused"
    )
    assert seen_after == collections.Counter(ok_tags + failed_tags), (
        f"the window holds {len(after)} records for {len(entries)} submitted payloads; missing "
        f"{sorted(set(ok_tags + failed_tags) - set(seen_after))[:5]!r}, unexpected "
        f"{sorted(set(seen_after) - set(ok_tags + failed_tags))[:5]!r}"
    )
    seqs = [r["SequenceNumber"] for r in after]
    assert len(set(seqs)) == len(seqs), (
        f"{len(seqs) - len(set(seqs))} of the {len(seqs)} records in the window share a "
        f"SequenceNumber; a sequence number identifies one record within a shard"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
