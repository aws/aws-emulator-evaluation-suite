"""kinpartial-resend-preserves-per-partition-key-ack-order."""
from __future__ import annotations

import collections
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

# A shard's write quota is reported per entry, so this is the one code a partially-failed entry
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

    DeleteStream is refused with ResourceInUseException while the stream is CREATING, so retry.
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
    """ACTIVE is not enough: ListShards can answer ResourceInUseException for a few seconds after
    DescribeStreamSummary reports ACTIVE, so the shards are polled for separately."""
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
    # the shard's own write quota reachable at all. It also puts every partition key on ONE shard,
    # which is what lets per-key order be compared against one total shard order.
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

    The index is deliberately not zero-padded, so byte order is not submission order.
    """
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

    A call-level throttle stores nothing, so re-issuing on exactly that code cannot duplicate.
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

    The shard's burst allowance accepts the opening calls whole; a call rejected whole is skipped.
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
    """Every record the shard holds AFTER ``after_seq``, read to the TIP, in shard order.

    ``MillisBehindLatest == 0`` is the observable condition meaning "this response is level with
    the end of the shard"; an empty page alone is not terminal, because GetRecords can return one
    before a just-written record becomes visible.
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
    """Resend ``entries``, retrying ONLY the entries whose own result carried an ErrorCode.

    Returns the acknowledgement order as ``[(tag, sequence_number), ...]``. A call that raises is
    fatal: its outcome is unknown, so a blind re-issue could store a record twice.
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


CHECK = "kinpartial-resend-preserves-per-partition-key-ack-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """After a partial PutRecords failure and a resend of only the refused entries, each partition
    key's records sit on the shard in acknowledgement order, not original submission order.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html
    """
    # Retries are disabled deliberately: a silently re-issued PutRecords call would insert a record
    # the acknowledgement log does not know about, and this file grades an order built from that log.
    c = ctx.client("kinesis", config=Config(retries={"max_attempts": 1, "mode": "standard"}))
    batch_size = 500
    record_size = 200
    keys = ["pk-alpha", "pk-bravo", "pk-charlie", "pk-delta"]

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Positive control: an all-valid batch over the same four keys comes back in submission order,
    # per key, with no entry refused. That is the no-recovery baseline this check departs from.
    control_start = _marker(c, name)
    control_entries = _entries("ctl", 12, 64, keys)
    control = _call_when_ready(lambda: c.put_records(StreamName=name, Records=control_entries))
    assert control["FailedRecordCount"] == 0, (
        f"the all-valid 12-record control batch reported FailedRecordCount "
        f"{control['FailedRecordCount']!r}: {control['Records']!r}"
    )
    control_window, _pages = _window_to_tip(c, name, shard_id, control_start, want=12)
    for key in keys:
        want = [_tag_of(e["Data"]) for e in control_entries if e["PartitionKey"] == key]
        got = [_tag_of(r["Data"]) for r in control_window if r["PartitionKey"] == key]
        assert got == want, (
            f"control: partition key {key!r} read back as {got!r}, not the submission order "
            f"{want!r}"
        )

    marker, entries, resp = _provoke_partial_batch(
        c, name, lambda attempt: _entries(f"a{attempt}", batch_size, record_size, keys)
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
    key_of = {_tag_of(e["Data"]): e["PartitionKey"] for e in entries}

    # The expectation is BUILT from the acknowledgements: the accepted entries of the first call in
    # request order, then whatever the resend leg acknowledged, in the order it acknowledged them.
    expected_order = [_tag_of(entries[i]["Data"]) for i in ok_idx]
    accepted_first_call = set(expected_order)
    acks = _resend_until_acknowledged(c, name, [entries[i] for i in failed_idx])
    expected_order += [tag for tag, _seq in acks]
    assert len(expected_order) == len(set(expected_order)) == len(entries), (
        f"the acknowledgement log names {len(expected_order)} records ("
        f"{len(set(expected_order))} distinct) for {len(entries)} submitted entries, so it cannot "
        f"be compared to the shard: duplicates "
        f"{[t for t, n in collections.Counter(expected_order).items() if n > 1][:5]!r}"
    )
    assert expected_order != sorted(expected_order), (
        "the expected order came out byte-sorted, so a target that serves records from a sorted "
        "structure would satisfy the order assertions below by accident rather than by preserving "
        "arrival order"
    )
    resent = [t for t in expected_order if t not in accepted_first_call]
    keys_with_both = {
        key for key in keys
        if any(key_of[t] == key for t in accepted_first_call)
        and any(key_of[t] == key for t in resent)
    }
    assert keys_with_both, (
        f"no partition key carries both an accepted and a resent record ("
        f"{len(accepted_first_call)} accepted, {len(resent)} resent over keys {keys!r}), so there "
        f"is no recovery order to grade and the assertions below would be vacuous"
    )

    window, _pages = _window_to_tip(c, name, shard_id, marker, want=len(entries))
    got_order = [_tag_of(r["Data"]) for r in window]
    assert collections.Counter(got_order) == collections.Counter(expected_order), (
        f"the shard holds {len(window)} records past the marker for {len(entries)} acknowledged "
        f"payloads; missing {sorted(set(expected_order) - set(got_order))[:5]!r}, unexpected "
        f"{sorted(set(got_order) - set(expected_order))[:5]!r}"
    )
    for r in window:
        assert r["PartitionKey"] == key_of[_tag_of(r["Data"])], (
            f"record {_tag_of(r['Data'])!r} was submitted under partition key "
            f"{key_of[_tag_of(r['Data'])]!r} and read back under {r['PartitionKey']!r}"
        )
    for key in sorted(keys_with_both):
        want = [t for t in expected_order if key_of[t] == key]
        got = [t for t in got_order if key_of[t] == key]
        first_divergence = next(
            (i for i, (a, b) in enumerate(zip(want, got)) if a != b), min(len(want), len(got))
        )
        assert got == want, (
            f"partition key {key!r} holds {len(got)} records in an order that diverges from the "
            f"acknowledgement order at position {first_divergence}: acknowledged "
            f"{want[max(0, first_divergence - 2):first_divergence + 3]!r}, read "
            f"{got[max(0, first_divergence - 2):first_divergence + 3]!r}. Records are replayed in "
            f"the order they arrived in the shard, and the resent entries arrived last"
        )
    seqs = [r["SequenceNumber"] for r in window]
    assert [int(s) for s in seqs] == sorted(int(s) for s in seqs), (
        f"the window's sequence numbers are not ascending in read order, so 'the order the shard "
        f"replays' is not a position in the shard: {seqs[:6]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
