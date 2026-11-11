"""kinpartial-oversized-entry-rejects-whole-batch-and-stores-nothing."""
from __future__ import annotations

import collections
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

THROTTLE = "ProvisionedThroughputExceededException"
# The per-record Data ceiling, in bytes: a fixed API constant, not an adjustable account quota.
MAX_RECORD_BYTES = 1048576


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

    DeleteStream is refused with ResourceInUseException while the stream is CREATING, so it retries.
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
    """Wait for ACTIVE, then for addressable shards.

    ListShards can answer ResourceInUseException for a few seconds after the stream reports ACTIVE.
    """
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
    # PROVISIONED with ShardCount=1 is the cheapest ACTIVE stream, and one shard means one total
    # order to read the effect back from.
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


def _client_error(fn, description):
    """The AWS Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{description} SUCCEEDED, where real AWS rejects the call outright")


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


def _window_to_tip(c, name, shard_id, after_seq, want, timeout_s=180, interval_s=1.0):
    """Every record the shard holds after ``after_seq``, read to the tip.

    An empty page is not terminal (GetRecords can return one before a write is visible), so the
    read stops only at ``MillisBehindLatest == 0``.
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


CHECK = "kinpartial-oversized-entry-rejects-whole-batch-and-stores-nothing"
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
    """One entry a single byte over the per-record ceiling rejects the whole PutRecords call with
    ValidationException and none of its valid siblings is stored; at exactly the ceiling it all lands.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html
    """
    # Retries are disabled deliberately, so a rejection surfaces to the check as itself rather than
    # being re-issued underneath it.
    c = ctx.client("kinesis", config=Config(retries={"max_attempts": 1, "mode": "standard"}))

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Positive control #1: an ordinary all-valid batch lands, so the stream, the shard and the
    # reader are known good before anything is expected to be absent.
    control_start = _marker(c, name)
    control_entries = _entries("ctl", 4, 64, ["pk-ctl"])
    control = _call_when_ready(lambda: c.put_records(StreamName=name, Records=control_entries))
    assert control["FailedRecordCount"] == 0, (
        f"the all-valid 4-record control batch reported FailedRecordCount "
        f"{control['FailedRecordCount']!r}: {control['Records']!r}"
    )
    control_window, _pages = _window_to_tip(c, name, shard_id, control_start, want=4)
    assert collections.Counter(_tag_of(r["Data"]) for r in control_window) == collections.Counter(
        _tag_of(e["Data"]) for e in control_entries
    ), (
        f"the control batch's 4 payloads read back as "
        f"{[_tag_of(r['Data']) for r in control_window]!r}"
    )

    # Break exactly one thing: ONE entry of five is a single byte over the per-record ceiling. The
    # other four are valid, uniquely tagged, and are what must be absent afterwards.
    subject_start = _marker(c, name)
    siblings = _entries("sib", 4, 64, ["pk-sib"])
    over_tag = b"over"
    oversized = {
        "Data": over_tag + b"." + b"o" * (MAX_RECORD_BYTES + 1 - len(over_tag) - 1),
        "PartitionKey": "pk-over",
    }
    batch = siblings[:2] + [oversized] + siblings[2:]
    assert len(oversized["Data"]) == MAX_RECORD_BYTES + 1, (
        f"the oversized entry is {len(oversized['Data'])} bytes, not one byte over the "
        f"{MAX_RECORD_BYTES}-byte ceiling; the rejection must be attributable to that one byte"
    )

    error = _client_error(
        lambda: c.put_records(StreamName=name, Records=batch),
        f"PutRecords with one {len(oversized['Data'])}-byte entry among four valid ones",
    )
    code = error.get("Code")
    assert code == "ValidationException", (
        f"PutRecords with one entry one byte over the {MAX_RECORD_BYTES}-byte ceiling was refused "
        f"with {code!r}; real AWS rejects the whole call at the request validator with exactly "
        f"'ValidationException' (a per-entry ErrorCode inside a 200 is the OTHER failure mode, and "
        f"confusing the two breaks every retrying producer)"
    )
    expected_message = (
        "1 validation error detected: Value at 'records.3.member.data' failed to satisfy "
        f"constraint: Member must have length less than or equal to {MAX_RECORD_BYTES}"
    )  # records.3 is the 1-based position of the oversized entry
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # The effect is ABSENT, per record: the call was atomic, so not one of the four valid siblings
    # was stored, and the shard has nothing at all past the marker.
    window, _pages = _window_to_tip(c, name, shard_id, subject_start, want=0)
    stored = [_tag_of(r["Data"]) for r in window]
    assert stored == [], (
        f"the call was refused whole, yet {len(stored)} records from it are on the shard: "
        f"{stored[:5]!r}. Valid entries submitted alongside a rejected one must not be stored — a "
        f"producer resending the batch entire, as a call-level rejection requires, would otherwise "
        f"duplicate exactly these"
    )

    # Positive control #2: the same five entries with the oversized one trimmed to exactly the
    # ceiling are wholly accepted, which pins the bound as inclusive and attributes the rejection
    # above to the single extra byte rather than to anything else about the batch.
    at_limit = {
        "Data": over_tag + b"." + b"o" * (MAX_RECORD_BYTES - len(over_tag) - 1),
        "PartitionKey": "pk-over",
    }
    assert len(at_limit["Data"]) == MAX_RECORD_BYTES, (
        f"the at-limit entry is {len(at_limit['Data'])} bytes, not exactly {MAX_RECORD_BYTES}"
    )
    retry_batch = siblings[:2] + [at_limit] + siblings[2:]
    accepted = _call_when_ready(lambda: c.put_records(StreamName=name, Records=retry_batch))
    assert accepted["FailedRecordCount"] == 0, (
        f"the same batch with its largest entry at exactly the {MAX_RECORD_BYTES}-byte ceiling "
        f"reported FailedRecordCount {accepted['FailedRecordCount']!r}: "
        f"{[r.get('ErrorCode') for r in accepted['Records']]!r}. The ceiling is inclusive"
    )
    final, _pages = _window_to_tip(c, name, shard_id, subject_start, want=len(retry_batch))
    seen = collections.Counter(_tag_of(r["Data"]) for r in final)
    assert seen == collections.Counter(_tag_of(e["Data"]) for e in retry_batch), (
        f"after the accepted resubmission the shard holds {len(final)} records past the marker "
        f"where {len(retry_batch)} are owed: {sorted(seen.items())!r}. Each payload — including the "
        f"{MAX_RECORD_BYTES}-byte one — is stored exactly once"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
