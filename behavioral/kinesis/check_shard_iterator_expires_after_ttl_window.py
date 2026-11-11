"""shard-iterator-expires-after-ttl-window."""
from __future__ import annotations

import re
import time
from typing import Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shard-iterator-expires-after-ttl-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]

# The message names the iterator's creation instant and the server's current one, which AWS
# chooses; the rest, including the 300000 ms tolerated delay, is fixed.
_DATE = r"[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4}"
_EXPIRED_ITERATOR_RE = re.compile(
    re.escape("Iterator expired. The iterator was created at time ") + _DATE
    + re.escape(" while right now it is ") + _DATE
    + re.escape(" which is further in the future than the tolerated delay of 300000 milliseconds.")
)


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """An iterator idle past its 5-minute TTL fails GetRecords with ExpiredIteratorException.

    Polls the same iterator until expiry, so the check does not rely on an exact T+300s boundary.
    """
    # A new stream with ShardCount=1 has exactly one shard, numbered from 0.
    shard_id = "shardId-000000000000"

    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-ttl-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "shard-iterator-ttl"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))

    # Issue the iterator before PutRecord so the idle clock starts as early as possible;
    # TRIM_HORIZON reads what is in the shard at GetRecords time.
    iterator = _get_shard_iterator_when_ready(ctx, stream_name, shard_id, "TRIM_HORIZON")
    iterator_issued_at = time.monotonic()

    kinesis.put_record(StreamName=stream_name, Data=b"payload-before-expiry", PartitionKey="pk-1")

    # Re-reading a valid iterator does not consume or refresh it, so polling is safe. The
    # deadline is anchored to iterator issuance so setup time does not shorten the idle wait.
    ttl_seconds = 5 * 60
    # The 5-minute TTL is not millisecond-exact; allow slack past it.
    expiry_buffer_s = 30.0
    poll_deadline = iterator_issued_at + ttl_seconds + expiry_buffer_s
    poll_interval_s = 1.0
    code: Optional[str] = None
    message = ""
    ever_valid = False
    while True:
        try:
            kinesis.get_records(ShardIterator=iterator)
            code = None  # still valid -- not yet expired
            ever_valid = True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "ExpiredIteratorException":
                break
        remaining = poll_deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval_s, remaining))

    elapsed = time.monotonic() - iterator_issued_at
    # Positive control: an iterator refused on first use cannot show accepted-then-expired.
    assert ever_valid, (
        f"the iterator was refused with {code!r} on its very first use, {elapsed:.0f}s after "
        f"GetShardIterator returned it; expected it to be usable before expiring"
    )
    assert code == "ExpiredIteratorException", (
        f"expected ExpiredIteratorException for an iterator idle {elapsed:.0f}s "
        f"(TTL is {ttl_seconds}s), got {code!r}"
    )
    assert _EXPIRED_ITERATOR_RE.fullmatch(message), f"unexpected expired-iterator message {message!r}"
    # It must not have expired suspiciously early either -- well before the documented 5-minute
    # TTL -- which would indicate the target is expiring iterators on some other, wrong basis.
    assert elapsed >= ttl_seconds - expiry_buffer_s, (
        f"iterator expired after only {elapsed:.0f}s, well short of the {ttl_seconds}s TTL"
    )

    # A fresh iterator obtained after the expiry must still work -- expiry is per-iterator, not per-stream.
    fresh_iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    fresh_resp = kinesis.get_records(ShardIterator=fresh_iterator)
    assert len(fresh_resp["Records"]) >= 1, "fresh iterator should still retrieve the earlier record"


def _get_shard_iterator_when_ready(
    ctx, stream_name: str, shard_id: str, iterator_type: str,
    timeout_s: float = 90.0, interval_s: float = 0.2,
) -> str:
    """Retry GetShardIterator through the transient window while the stream is still CREATING."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.get_shard_iterator(
                StreamName=stream_name, ShardId=shard_id, ShardIteratorType=iterator_type
            )["ShardIterator"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceInUseException", "ResourceNotFoundException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
