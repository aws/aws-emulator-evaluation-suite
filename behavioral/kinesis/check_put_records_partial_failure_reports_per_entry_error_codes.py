"""put-records-partial-failure-reports-per-entry-error-codes."""
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


def _drain_to_tip(c, iterator, want, timeout_s=180, interval_s=1.0, limit=1000):
    """Collect >= ``want`` records AND read to the TIP of the shard.

    MillisBehindLatest == 0 is the observable condition meaning "this response is level with the
    end of the shard, there is nothing further to read". It is what makes an assertion about
    records that must be ABSENT from a shard meaningful: an empty page on its own is not
    terminal, because GetRecords legitimately returns one before a just-written record becomes
    visible. Returns ``(records, next_iterator, pages)``; ``next_iterator`` is None once the
    shard is closed, which is a distinct terminal signal from "level with the tip".
    """
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        at_tip = resp.get("MillisBehindLatest") == 0
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, None, pages
        iterator = nxt
        if len(collected) >= want and at_tip:
            return collected, iterator, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {pages} GetRecords pages over {timeout_s}s and saw "
                f"{len(collected)} of {want} expected records, MillisBehindLatest="
                f"{resp.get('MillisBehindLatest')!r}: "
                f"{[bytes(r['Data']) for r in collected]!r}"
            )
        time.sleep(interval_s)


def _tag_of(data):
    """The unique tag a padded record carries in front of its padding."""
    return bytes(data).split(b".", 1)[0]


def _padded_entries(prefix, count, size, partition_key):
    """``count`` PutRecords entries of ``size`` bytes each, every one uniquely tagged."""
    entries = []
    for i in range(count):
        tag = f"{prefix}-{i:03d}".encode()
        entries.append({
            "Data": tag + b"." + b"p" * (size - len(tag) - 1),
            "PartitionKey": partition_key,
        })
    return entries


CHECK = "put-records-partial-failure-reports-per-entry-error-codes"
GROUP = 'data-plane'
SERVICES = ['kinesis']


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A PutRecords batch over a shard's ingest quota is partially accepted per entry: Records[]
    stays aligned, failed entries carry the throughput ErrorCode and exact ErrorMessage and are not
    stored until resent.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html
    """
    c = ctx.client("kinesis")
    # An oversized (>1 MiB) entry rejects the whole call with ValidationException; the per-entry
    # failure mode is the shard's throughput quota, so this overshoots it inside one call.
    record_size = 10 * 1024
    batch_size = 450          # 450 x 10 KiB = 4.4 MiB in one call: under the 5 MiB / 500-entry
                              # call limits, and 4.4x a single shard's 1 MiB/s ingest quota.
    expected_code = "ProvisionedThroughputExceededException"

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Positive control, established FIRST: a small all-valid batch is fully accepted, every entry
    # carries a SequenceNumber and none carries an ErrorCode. Everything below differs from this
    # only in volume.
    control_entries = _padded_entries("ctl", 3, 256, "pk-ctl")
    control = _call_when_ready(lambda: c.put_records(StreamName=name, Records=control_entries))
    assert control["FailedRecordCount"] == 0, (
        f"the all-valid 3-record control batch reported FailedRecordCount "
        f"{control['FailedRecordCount']!r}: {control['Records']!r}"
    )
    assert len(control["Records"]) == len(control_entries), (
        f"the control batch returned {len(control['Records'])} result entries for "
        f"{len(control_entries)} request entries; Records[] is positionally aligned and is never "
        f"compacted"
    )
    for i, r in enumerate(control["Records"]):
        assert r.get("SequenceNumber") and not r.get("ErrorCode"), (
            f"control entry {i} is {r!r}; a successful entry carries SequenceNumber + ShardId and "
            f"no ErrorCode"
        )
    accepted_tags = [_tag_of(e["Data"]) for e in control_entries]

    # Break exactly one thing: the volume in a single call. Bounded retry on the observable
    # condition "the shard reported at least one per-entry failure", because a quota is measured
    # per second and the first call may land inside a burst allowance.
    resp = None
    entries = None
    for attempt in range(4):
        entries = _padded_entries(f"b{attempt}", batch_size, record_size, "pk-bulk")
        resp = _call_when_ready(lambda e=entries: c.put_records(StreamName=name, Records=e))
        if resp["FailedRecordCount"] > 0:
            break
        # Every entry of a fully-accepted attempt is really on the shard and is accounted for.
        accepted_tags.extend(_tag_of(e["Data"]) for e in entries)
    assert resp["FailedRecordCount"] > 0, (
        f"{4 * batch_size} records of {record_size} bytes ("
        f"{round(4 * batch_size * record_size / 1048576, 1)} MiB) were written to a ONE-shard "
        f"stream in 4 back-to-back PutRecords calls and every entry was accepted. A shard ingests "
        f"1 MiB/s, and Kinesis reports the overflow per entry rather than refusing the call, so at "
        f"least one entry must fail with {expected_code!r}"
    )

    results = resp["Records"]
    assert len(results) == len(entries), (
        f"PutRecords returned {len(results)} result entries for {len(entries)} request entries; "
        f"Records[] is positionally aligned with the request and must never be compacted — a "
        f"producer resends by index"
    )

    failed_idx = [i for i, r in enumerate(results) if r.get("ErrorCode")]
    ok_idx = [i for i, r in enumerate(results) if not r.get("ErrorCode")]
    assert resp["FailedRecordCount"] == len(failed_idx), (
        f"FailedRecordCount is {resp['FailedRecordCount']!r} but {len(failed_idx)} of "
        f"{len(results)} result entries carry an ErrorCode; the count and the array must agree"
    )
    codes = {results[i]["ErrorCode"] for i in failed_idx}
    assert codes == {expected_code}, (
        f"the failed entries carry error codes {sorted(codes)!r}; overflowing a shard's ingest "
        f"quota is reported per entry as exactly {expected_code!r}"
    )
    messages = {results[i].get("ErrorMessage") for i in failed_idx}
    want_message = f"Rate exceeded for shard {shard_id} in stream {name} under account {ctx.account}."
    assert messages == {want_message}, (
        f"the refused entries carry error messages {messages!r}; expected only {want_message!r}"
    )
    for i in failed_idx:
        r = results[i]
        assert r.get("ErrorMessage") and "SequenceNumber" not in r and "ShardId" not in r, (
            f"failed result entry {i} is {r!r}; a failed entry carries ErrorCode + ErrorMessage "
            f"and NEITHER SequenceNumber nor ShardId — the two members are exclusive"
        )
    for i in ok_idx:
        r = results[i]
        assert r.get("SequenceNumber") and r.get("ShardId") == shard_id, (
            f"successful result entry {i} is {r!r}; it must carry a SequenceNumber and the only "
            f"shard {shard_id!r}"
        )
    assert ok_idx, (
        f"every one of {len(results)} entries failed, so this is a whole-call rejection wearing a "
        f"200 rather than the partial acceptance the check grades: {results[0]!r}"
    )

    failed_tags = [_tag_of(entries[i]["Data"]) for i in failed_idx]
    accepted_tags.extend(_tag_of(entries[i]["Data"]) for i in ok_idx)

    # Effect absent, BEFORE any retry: the shard holds exactly the acknowledged records. A
    # throttled entry was not stored, which is precisely why a producer may safely resend it.
    def _tags_on_shard(want):
        it = c.get_shard_iterator(
            StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        recs, _next_it, _pages = _drain_to_tip(c, it, want=want, timeout_s=240)
        return [_tag_of(r["Data"]) for r in recs]

    before_retry = _tags_on_shard(len(accepted_tags))
    leaked = sorted(set(failed_tags) & set(before_retry))
    assert not leaked, (
        f"{len(leaked)} of the {len(failed_tags)} entries that were reported failed with "
        f"{expected_code!r} are readable from the shard anyway: {leaked[:5]!r}. A producer that "
        f"resends them, as the ErrorCode instructs, would then have duplicated them"
    )
    missing = sorted(set(accepted_tags) - set(before_retry))
    assert not missing, (
        f"{len(missing)} entries that PutRecords ACKNOWLEDGED with a SequenceNumber are not "
        f"readable from the shard: {missing[:5]!r}"
    )

    # Recovery: resend only the failed subset, in chunks below the shard's per-second quota. This
    # is the producer contract the per-entry ErrorCode exists for.
    pending = [entries[i] for i in failed_idx]
    rounds = 0
    while pending and rounds < 20:
        rounds += 1
        chunk, pending = pending[:80], pending[80:]
        retry = _call_when_ready(lambda ch=chunk: c.put_records(StreamName=name, Records=ch))
        pending.extend(
            chunk[i] for i, r in enumerate(retry["Records"]) if r.get("ErrorCode")
        )
        time.sleep(1.0)
    assert not pending, (
        f"{len(pending)} of the {len(failed_tags)} throttled entries were still unaccepted after "
        f"{rounds} bounded retry rounds of 80 records each"
    )

    # Coverage, not an exact count: Kinesis does not promise exactly-once across a producer retry.
    after_retry = set(_tags_on_shard(len(accepted_tags) + len(failed_tags)))
    still_missing = sorted(set(failed_tags) - after_retry)
    assert not still_missing, (
        f"{len(still_missing)} entries were accepted on retry but are not readable from the "
        f"shard: {still_missing[:5]!r}"
    )
    assert set(accepted_tags) <= after_retry, (
        f"records acknowledged before the retry are no longer readable: "
        f"{sorted(set(accepted_tags) - after_retry)[:5]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
