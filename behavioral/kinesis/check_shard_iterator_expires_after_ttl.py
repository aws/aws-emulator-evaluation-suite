"""shard-iterator-expires-after-ttl."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "shard-iterator-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A shard iterator obtained from GetShardIterator is valid immediately, but becomes
    permanently invalid for GetRecords once its documented 5-minute TTL elapses -- distinct
    from a generic malformed/garbage-iterator rejection check."""
    # The documented iterator TTL is 5 minutes, so this check waits it out (timing:real-time).
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": "kinesis-behav"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    shard_id = _first_shard_id(kinesis, name)

    kinesis.put_record(StreamName=name, Data=b"seed", PartitionKey="k")

    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    issued_at = time.monotonic()

    # Positive control: the freshly issued iterator works right away.
    initial = kinesis.get_records(ShardIterator=iterator, Limit=10)
    assert len(initial["Records"]) == 1, (
        f"expected the freshly issued iterator to return the 1 seeded record, "
        f"got {len(initial['Records'])}"
    )

    # "A shard iterator expires 5 minutes after it is returned to the requester."
    # https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
    # Keep polling with the ORIGINAL iterator string (never NextShardIterator, which would just
    # give us a fresh TTL) until the service rejects it.
    deadline = time.monotonic() + 400
    code = None
    message = None
    while time.monotonic() < deadline:
        try:
            kinesis.get_records(ShardIterator=iterator, Limit=10)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
            if code == "ExpiredIteratorException":
                break
            raise AssertionError(f"unexpected error before TTL elapsed: {code}: {message}") from err
        time.sleep(15)

    elapsed = time.monotonic() - issued_at
    assert code == "ExpiredIteratorException", (
        f"expected ExpiredIteratorException once the iterator's TTL elapsed, got {code!r} "
        f"after {elapsed:.0f}s"
    )
    # message varies: AWS embeds the iterator's server-side creation time and the server's
    # current time, to the second. Both are read back out of the message, and the message is
    # rebuilt around them, so every other character is graded exactly.
    times = _EXPIRED_TIMES_RE.fullmatch(message or "")
    created, now = times.groups() if times else ("<unparsed>", "<unparsed>")
    expected_message = _EXPIRED_TEMPLATE.format(created=created, now=now)
    assert message == expected_message, (
        f"ExpiredIteratorException message {message!r} != {expected_message!r}"
    )
    # Must not have expired suspiciously early (well before the documented 5-minute window).
    assert elapsed >= 290, (
        f"iterator expired after only {elapsed:.0f}s; the documented TTL is ~300s, so expiry "
        f"well before 290s would mean the target is expiring iterators early"
    )


_EXPIRED_TEMPLATE = (
    "Iterator expired. The iterator was created at time {created} while right now it is {now} "
    "which is further in the future than the tolerated delay of 300000 milliseconds."
)
_EXPIRED_TIMES_RE = re.compile(
    re.escape(_EXPIRED_TEMPLATE)
    .replace(re.escape("{created}"), "(.+?)")
    .replace(re.escape("{now}"), "(.+?)")
)


def _wait_stream_active(kinesis, name, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s (last={summary})")


def _first_shard_id(kinesis, name, timeout_s=90.0, interval_s=2.0):
    """ListShards can still answer ResourceInUseException (CREATING) just after the summary
    reads ACTIVE; retry through that window, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.list_shards(StreamName=name)["Shards"][0]["ShardId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
