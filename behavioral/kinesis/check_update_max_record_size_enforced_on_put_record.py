"""update-max-record-size-enforced-on-put-record."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-max-record-size-enforced-on-put-record"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After UpdateMaxRecordSize lowers the per-record limit, PutRecord with a payload that
    exceeds the new (lower) limit is server-side rejected even though an identical payload was
    accepted moments earlier under the higher limit -- and no such record is written."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    summary = _wait_stream_active(kinesis, name)
    stream_arn = summary["StreamARN"]

    # 1.5 MiB: between the default 1024 KiB limit and the raised 2048 KiB limit.
    payload = b"r" * (1536 * 1024)

    # UpdateMaxRecordSize only accepts StreamARN (StreamName is rejected client-side by botocore
    # as an unknown parameter for this operation).
    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=2048)
    _wait_max_record_size(kinesis, name, 2048)

    accepted = kinesis.put_record(StreamName=name, Data=payload, PartitionKey="k1")
    assert "SequenceNumber" in accepted, f"positive control: 1.5MiB payload rejected under the raised 2048 KiB limit: {accepted}"
    # Same partition key -> deterministically the same shard for every write in this check.
    shard_id = accepted["ShardId"]
    accepted_sequence_numbers = [accepted["SequenceNumber"]]

    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=1024)
    _wait_max_record_size(kinesis, name, 1024)

    # DescribeStreamSummary confirming the new (lower) MaxRecordSizeInKiB does not guarantee the
    # data plane has already picked it up, so bounded-poll the oversized PutRecord until the
    # server actually starts rejecting it -- any transient acceptance during that propagation
    # window is a real record, tracked so the final "no trace" check stays exact rather than
    # assuming a hardcoded record count.
    deadline = time.monotonic() + 90
    code = message = None
    while time.monotonic() < deadline:
        try:
            resp = kinesis.put_record(StreamName=name, Data=payload, PartitionKey="k1")
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
            break
        else:
            accepted_sequence_numbers.append(resp["SequenceNumber"])
            time.sleep(3)
    # Real AWS rejects a PutRecord whose payload exceeds the configured MaxRecordSizeInKiB with
    # a generic ValidationException (schema-level size-constraint violation tied to the current
    # per-stream max), matching the same error shape UpdateMaxRecordSize itself uses for an
    # out-of-range value -- not the domain-specific InvalidArgumentException.
    assert code == "ValidationException", f"lowered limit never enforced within 90s (last code={code})"
    expected_message = (
        "1 validation error detected: Value at 'data' failed to satisfy constraint: "
        f"Member must have length less than or equal to {1024 * 1024}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Confirm the rejection is stable, not a one-off blip.
    code2, message2 = _error_code(lambda: kinesis.put_record(StreamName=name, Data=payload, PartitionKey="k1"))
    assert code2 == "ValidationException", f"expected the second oversized attempt to also be rejected, got code={code2}"
    assert message2 == expected_message, f"expected message {expected_message!r}, got {message2!r}"

    # Restore: raise the limit back to 2048 and confirm the identical call that was just
    # rejected now succeeds again -- the rejection is tied to the current configured limit,
    # not a one-way ratchet the server latches once tripped.
    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=2048)
    _wait_max_record_size(kinesis, name, 2048)
    restored = kinesis.put_record(StreamName=name, Data=payload, PartitionKey="k1")
    assert "SequenceNumber" in restored, f"restore: identical payload rejected again after raising the limit back to 2048: {restored}"
    accepted_sequence_numbers.append(restored["SequenceNumber"])

    # The rejected PutRecord attempts left no trace: the shard holds exactly the accepted
    # records (in submission order), never a record for a rejected oversized attempt.
    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records = _read_records(kinesis, iterator, len(accepted_sequence_numbers))
    assert [r["SequenceNumber"] for r in records] == accepted_sequence_numbers, (
        f"shard {shard_id} holds unexpected records: "
        f"expected {accepted_sequence_numbers}, got {[r['SequenceNumber'] for r in records]}"
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


def _wait_max_record_size(kinesis, name, target_kib, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary.get("MaxRecordSizeInKiB") == target_kib:
            return summary
        time.sleep(interval_s)
    raise AssertionError(
        f"stream {name} MaxRecordSizeInKiB never reached {target_kib} within {timeout_s}s (last={summary})"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result}")


def _read_records(kinesis, iterator, count, timeout_s=60.0, interval_s=1.0, **kwargs):
    """Records read along NextShardIterator until at least count arrive or timeout_s passes:
    GetRecords may return an empty page while data is still pending."""
    records = []
    deadline = time.monotonic() + timeout_s
    while iterator and time.monotonic() < deadline:
        page = kinesis.get_records(ShardIterator=iterator, **kwargs)
        records.extend(page["Records"])
        iterator = page.get("NextShardIterator")
        if len(records) >= count:
            return records
        time.sleep(interval_s)
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
