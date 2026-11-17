"""get-records-limit-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-records-limit-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _until_addressable(fn, timeout_s=90.0, interval_s=2.0):
    """Retries ``fn`` through the brief window after a stream reports ACTIVE where its data
    plane still answers ResourceNotFoundException / ResourceInUseException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _unvalidated_client(ctx):
    """A kinesis client with local parameter validation off, so an out-of-range Limit reaches AWS."""
    return ctx.client("kinesis", config=Config(parameter_validation=False))


def _client_error(fn) -> dict:
    """The Error dict ``fn``'s call raises. An unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecords with a Limit above 10000 is refused with its exact ValidationException message,
    while the maximum in-range Limit of 10000 still returns the record just written."""
    kinesis = ctx.client("kinesis")
    raw = _unvalidated_client(ctx)
    name = ctx.unique_name("sim2real-behav-grl-")

    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)

    put = _until_addressable(
        lambda: kinesis.put_record(StreamName=name, Data=b"grl-payload", PartitionKey="grl-key")
    )
    shard_id = put["ShardId"]

    error = _client_error(lambda: raw.get_records(
        ShardIterator=kinesis.get_shard_iterator(
            StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON",
        )["ShardIterator"],
        Limit=10001,
    ))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for Limit=10001, got {error.get('Code')!r}: {error.get('Message')!r}"
    )
    expected_message = (
        "1 validation error detected: Value '10001' at 'limit' failed to satisfy constraint: "
        "Member must have value less than or equal to 10000"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    control_iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]
    # GetRecords may return an empty batch with a NextShardIterator before the record; follow it.
    records, iterator = [], control_iterator
    for _ in range(20):
        ok = kinesis.get_records(ShardIterator=iterator, Limit=10000)
        records, iterator = ok["Records"], ok.get("NextShardIterator")
        if records or iterator is None:
            break
        time.sleep(1)
    assert len(records) == 1 and records[0]["Data"] == b"grl-payload", (
        f"Limit=10000 (the maximum in-range value) must still return the record written, got {records!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
