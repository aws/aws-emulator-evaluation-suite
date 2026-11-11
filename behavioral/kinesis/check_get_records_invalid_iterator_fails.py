"""get-records-invalid-iterator-fails."""
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

def _error(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

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

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

CHECK = "get-records-invalid-iterator-fails"
GROUP = 'error-semantics'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecords with a malformed shard iterator fails with InvalidArgumentException and its exact
    message, while a positive control proves GetRecords works on the stream with a real iterator."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = c.list_shards(StreamName=name)["Shards"][0]["ShardId"]

    # Positive control: GetRecords works on this stream at all, with a real iterator.
    good_iterator = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    control_resp = c.get_records(ShardIterator=good_iterator, Limit=10)
    assert control_resp.get("NextShardIterator") is not None, (
        f"a freshly issued shard iterator was rejected by GetRecords: "
        f"{ {k: v for k, v in control_resp.items() if k != 'Records'} !r}; without this control, "
        f"a malformed-iterator rejection below cannot be told apart from GetRecords failing "
        f"outright on this stream"
    )

    # Malformed, not aged: ExpiredIteratorException would be the wrong code here.
    code, message = _error(lambda: c.get_records(ShardIterator="not-a-real-iterator"))
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for a malformed shard iterator, got {code}"
    )
    assert message == "Invalid ShardIterator.", f"expected message 'Invalid ShardIterator.', got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
