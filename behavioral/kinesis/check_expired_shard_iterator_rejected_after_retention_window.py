"""expired-shard-iterator-rejected-after-retention-window."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# CreateStream carries Tags= so tag-based cleanup can discover the stream.


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


CHECK = "expired-shard-iterator-rejected-after-retention-window"
GROUP = 'data-plane'
SERVICES = ['kinesis']

# The message names the iterator's creation instant and the server's current one, which AWS
# chooses; the rest, including the 300000 ms tolerated delay, is fixed.
_DATE = r"[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4}"
_EXPIRED_ITERATOR_RE = re.compile(
    re.escape("Iterator expired. The iterator was created at time ") + _DATE
    + re.escape(" while right now it is ") + _DATE
    + re.escape(" which is further in the future than the tolerated delay of 300000 milliseconds.")
)


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
@tags("axis:rejection", "concern:negative-classes", "dp:api", "plane:data", "cap:c2", "timing:real-time")
def run(ctx) -> None:
    """GetRecords accepts a shard iterator, then refuses the same string once it has aged out.
    The refusal is ExpiredIteratorException and a fresh iterator still reads every record.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
    """
    c = ctx.client("kinesis")
    payloads = [b"exp-alpha", b"exp-beta", b"exp-gamma"]
    expected_code = "ExpiredIteratorException"

    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _get_shards(c, name)[0]["ShardId"]

    # Take the iterator that will be aged out FIRST, so its 5-minute clock overlaps every other
    # step in this check rather than following them.
    stale = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    issued_at = time.monotonic()

    # Positive control on the very iterator that will later be refused: GetRecords accepts it while it is fresh.
    # Without this the refusal below could be about a malformed iterator rather than an aged one.
    fresh_resp = c.get_records(ShardIterator=stale, Limit=10)
    assert fresh_resp.get("NextShardIterator") is not None, (
        f"the iterator just returned by GetShardIterator was not usable: GetRecords answered "
        f"{ {k: v for k, v in fresh_resp.items() if k != 'Records'} !r}"
    )

    for i, payload in enumerate(payloads):
        resp = _call_when_ready(
            lambda p=payload: c.put_record(StreamName=name, Data=p, PartitionKey="same-key")
        )
        assert resp["ShardId"] == shard_id, (
            f"record {i} ({payload!r}) landed on {resp['ShardId']!r}, not the only shard "
            f"{shard_id!r}"
        )

    # Second control: a fresh iterator reads all three records, so the shard and the data are
    # sound before any waiting happens.
    control_it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    control_recs, _next_it, control_pages = _drain(c, control_it, want=len(payloads))
    control_payloads = [bytes(r["Data"]) for r in control_recs]
    assert control_payloads == payloads, (
        f"a fresh iterator read {control_payloads!r} over {control_pages} pages before any wait, "
        f"expected {payloads!r}"
    )

    # Re-use the SAME iterator string until it is refused; only its age changes. AWS expires an
    # iterator 5 minutes after issue, so this loop is bounded at 480 s rather than shortened.
    accepted_ages = []
    code = None
    message = ""
    deadline = issued_at + 480
    while True:
        try:
            c.get_records(ShardIterator=stale, Limit=10)
            accepted_ages.append(round(time.monotonic() - issued_at, 1))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            break
        assert time.monotonic() < deadline, (
            f"the same shard iterator was still accepted {round(time.monotonic() - issued_at)}s "
            f"after GetShardIterator returned it (accepted at ages {accepted_ages!r}); real AWS "
            f"expires a shard iterator 5 minutes after issuing it, and an iterator that never "
            f"expires lets a consumer resume from a position the service can no longer trim"
        )
        time.sleep(10)

    expired_at = round(time.monotonic() - issued_at, 1)
    assert code == expected_code, (
        f"GetRecords with a {expired_at}s-old shard iterator failed with {code!r}; real AWS "
        f"answers {expected_code!r}. The identical iterator string was accepted at ages "
        f"{accepted_ages!r}, so this is the age of the iterator and nothing else"
    )
    assert _EXPIRED_ITERATOR_RE.fullmatch(message), f"unexpected expired-iterator message {message!r}"
    assert accepted_ages, (
        f"the iterator was refused with {code!r} on its very first use, {expired_at}s after "
        f"GetShardIterator returned it; the transition this check grades is accepted-then-refused, "
        f"and an iterator that is never usable cannot exhibit it"
    )

    # Effect absent: nothing about the stream changed. A fresh iterator still serves all three
    # records in order, so only the iterator aged.
    after_it = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    after_recs, _after_next, after_pages = _drain(c, after_it, want=len(payloads))
    after_payloads = [bytes(r["Data"]) for r in after_recs]
    assert after_payloads == payloads, (
        f"after the stale iterator was refused, a fresh iterator read {after_payloads!r} over "
        f"{after_pages} pages, expected the same {payloads!r}; iterator expiry must not touch the "
        f"records"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
