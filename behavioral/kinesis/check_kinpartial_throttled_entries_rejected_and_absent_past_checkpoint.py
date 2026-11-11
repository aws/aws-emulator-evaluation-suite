"""kinpartial-throttled-entries-rejected-and-absent-past-checkpoint."""
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
    """Every record the shard holds AFTER ``after_seq``, read to the TIP.

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


CHECK = "kinpartial-throttled-entries-rejected-and-absent-past-checkpoint"
GROUP = "data-plane"
SERVICES = ["kinesis"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """Entries PutRecords refused with a throughput error are absent from the shard, durably: the last
    acknowledged SequenceNumber stays the tip, and a later write is still read past it.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html
    """
    # Retries are disabled deliberately: a throttle must surface to the check rather than being
    # smoothed away under it, and a silently re-issued PutRecords call would duplicate records.
    c = ctx.client("kinesis", config=Config(retries={"max_attempts": 1, "mode": "standard"}))
    batch_size = 500
    record_size = 200
    rereads = 5

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Positive control, established FIRST: an all-valid batch is wholly accepted and every payload
    # is readable back. Everything below differs from it only in submission rate.
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
        f"{[_tag_of(r['Data']) for r in control_window]!r}; the reader and the window mechanism "
        f"this check uses for its absence assertions must be able to see accepted records"
    )

    # Break exactly one thing: the submission rate into a single shard.
    marker, entries, resp = _provoke_partial_batch(
        c, name, lambda attempt: _entries(f"a{attempt}", batch_size, record_size, ["pk-bulk"])
    )
    results = resp["Records"]
    failed_idx = [i for i, r in enumerate(results) if r.get("ErrorCode")]
    ok_idx = [i for i, r in enumerate(results) if not r.get("ErrorCode")]
    assert resp["FailedRecordCount"] == len(failed_idx), (
        f"FailedRecordCount is {resp['FailedRecordCount']!r} but {len(failed_idx)} of "
        f"{len(results)} result entries carry an ErrorCode; the count and the array must agree"
    )
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
    for i in failed_idx:
        r = results[i]
        assert r.get("ErrorMessage") and "SequenceNumber" not in r and "ShardId" not in r, (
            f"refused result entry {i} is {r!r}; a refused entry carries ErrorCode + ErrorMessage "
            f"and NEITHER SequenceNumber nor ShardId — the two are exclusive, and a refused entry "
            f"has no position in the shard to name"
        )
    for i in ok_idx:
        r = results[i]
        assert r.get("SequenceNumber") and r.get("ShardId") == shard_id, (
            f"acknowledged result entry {i} is {r!r}; it must carry a SequenceNumber and the only "
            f"shard {shard_id!r}"
        )
    ok_tags = [_tag_of(entries[i]["Data"]) for i in ok_idx]
    failed_tags = [_tag_of(entries[i]["Data"]) for i in failed_idx]

    # The effect is ABSENT, per record: the window holds exactly the acknowledged payloads.
    window, _pages = _window_to_tip(c, name, shard_id, marker, want=len(ok_idx))
    seen = collections.Counter(_tag_of(r["Data"]) for r in window)
    assert seen == collections.Counter(ok_tags), (
        f"one PutRecords call acknowledged {len(ok_idx)} entries and refused {len(failed_idx)} "
        f"with {THROTTLE!r}, and the shard holds {len(window)} records past the marker: refused "
        f"payloads present {sorted(set(failed_tags) & set(seen))[:5]!r}, acknowledged payloads "
        f"missing {sorted(set(ok_tags) - set(seen))[:5]!r}, payloads stored more than once "
        f"{[t for t, n in seen.items() if n > 1][:5]!r}"
    )

    # And the absence is durable, not a read that merely arrived early: re-read the same window.
    for round_i in range(rereads):
        time.sleep(1.0)
        again, _pages = _window_to_tip(c, name, shard_id, marker, want=len(ok_idx))
        seen_again = collections.Counter(_tag_of(r["Data"]) for r in again)
        assert seen_again == seen, (
            f"re-read {round_i + 1} of {rereads} of the same window returned "
            f"{len(again)} records where the first read returned {len(window)}: newly appeared "
            f"{sorted(set(seen_again) - set(seen))[:5]!r} (of which refused-and-arriving-late "
            f"{sorted((set(seen_again) - set(seen)) & set(failed_tags))[:5]!r}), disappeared "
            f"{sorted(set(seen) - set(seen_again))[:5]!r}"
        )

    # The consumer-checkpoint consequence: the LAST acknowledged record is the tip of the shard.
    # A producer that resends from its last acknowledged SequenceNumber loses nothing, because
    # nothing was appended after it.
    last_ack = max((r["SequenceNumber"] for r in window), key=int)
    tail, _pages = _window_to_tip(c, name, shard_id, last_ack, want=0)
    assert tail == [], (
        f"{len(tail)} records sit past the last acknowledged SequenceNumber {last_ack!r} while the "
        f"shard reports itself level with the tip: {[_tag_of(r['Data']) for r in tail][:5]!r}. "
        f"Every entry of that call was either acknowledged before it or refused"
    )

    # Positive control for the absence itself: the same reader, the same iterator type and the same
    # checkpoint DO deliver a record written after it. Without this, an empty window above would be
    # evidence about the reader rather than about the refused entries.
    after_entry = _entries("post", 1, 64, ["pk-bulk"])[0]
    _call_when_ready(lambda: c.put_records(StreamName=name, Records=[after_entry]))
    tail_again, _pages = _window_to_tip(c, name, shard_id, last_ack, want=1)
    assert [_tag_of(r["Data"]) for r in tail_again] == [_tag_of(after_entry["Data"])], (
        f"a record written after checkpoint {last_ack!r} read back as "
        f"{[_tag_of(r['Data']) for r in tail_again]!r}, not exactly "
        f"[{_tag_of(after_entry['Data'])!r}]; the empty window asserted above has to mean 'nothing "
        f"was stored', not 'this reader cannot see anything'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
