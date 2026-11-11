"""get-shard-iterator-ttl-expires-after-inactivity."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "get-shard-iterator-ttl-expires-after-inactivity"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]

# Documented behavior: "A shard iterator expires 5 minutes after it is returned
# to the requester" if it is never used to call GetRecords.
# https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetRecords.html
_ITERATOR_TTL_S = 300

# The message names the iterator's creation instant and the server's current one, which AWS
# chooses; the rest, including the 300000 ms tolerated delay, is fixed.
_DATE = r"[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4}"
_EXPIRED_ITERATOR_RE = re.compile(
    re.escape("Iterator expired. The iterator was created at time ") + _DATE
    + re.escape(" while right now it is ") + _DATE
    + re.escape(" which is further in the future than the tolerated delay of 300000 milliseconds.")
)


def _poll_error(fn, deadline, interval_s=10):
    """The botocore Error dict ``fn`` raises, re-calling it until ``deadline``; still succeeding
    at the deadline raises AssertionError."""
    from botocore.exceptions import ClientError

    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(
                f"expected the idle iterator to be rejected by the deadline, but GetRecords "
                f"still SUCCEEDED and returned {result!r}"
            )
        time.sleep(min(interval_s, remaining))


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A shard iterator left unused past its 5-minute validity fails GetRecords with
    ExpiredIteratorException, while a freshly obtained iterator on the same shard still works.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetRecords.html"""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(ctx, name)

    put = _call_when_ready(
        lambda: kinesis.put_record(StreamName=name, Data=b"ttl-probe", PartitionKey="ttl-probe")
    )
    shard_id = put["ShardId"]

    # Positive control: a fresh iterator used immediately returns the record.
    fresh_iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    baseline = kinesis.get_records(ShardIterator=fresh_iterator, Limit=10)
    assert len(baseline["Records"]) == 1, (
        f"expected 1 record on the freshly obtained iterator, got {len(baseline['Records'])}"
    )

    stale_iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    issued_at = time.monotonic()

    # Re-reading a still-valid iterator does not refresh it, so polling up to the deadline
    # (anchored to issuance) is safe and catches expiry when it happens.
    deadline = issued_at + _ITERATOR_TTL_S + 120
    error = _poll_error(lambda: kinesis.get_records(ShardIterator=stale_iterator, Limit=10), deadline)
    code = error.get("Code")
    elapsed = time.monotonic() - issued_at
    assert code == "ExpiredIteratorException", (
        f"expected ExpiredIteratorException for an iterator idle {elapsed:.0f}s "
        f"(TTL is {_ITERATOR_TTL_S}s), got {code!r}"
    )
    message = error.get("Message", "")
    assert _EXPIRED_ITERATOR_RE.fullmatch(message), f"unexpected expired-iterator message {message!r}"

    # Expiry is scoped to the stale iterator: a brand new one still works.
    control_iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    control = kinesis.get_records(ShardIterator=control_iterator, Limit=10)
    assert len(control["Records"]) == 1, (
        f"expected the fresh control iterator to still see 1 record, got {len(control['Records'])}"
    )
    assert control["Records"][0]["Data"] == b"ttl-probe", (
        f"expected control record data b'ttl-probe', got {control['Records'][0]['Data']!r}"
    )


def _call_when_ready(fn, timeout_s=90.0, interval_s=2.0):
    """Retry ``fn`` while the data plane still reports the just-ACTIVE stream as missing or busy."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("ResourceNotFoundException", "ResourceInUseException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
