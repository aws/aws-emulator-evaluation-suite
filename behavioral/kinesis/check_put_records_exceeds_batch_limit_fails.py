"""put-records-exceeds-batch-limit-fails."""
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
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
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
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _read_records(c, name, shard_id):
    iterator = c.get_shard_iterator(StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON")[
        "ShardIterator"
    ]
    return c.get_records(ShardIterator=iterator, Limit=1000)["Records"]

CHECK = "put-records-exceeds-batch-limit-fails"
GROUP = 'data-plane'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecords with more than 500 records fails whole-call with ValidationException (not
    InvalidArgumentException), and none of the offered records land on the shard."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = c.list_shards(StreamName=name)["Shards"][0]["ShardId"]

    control_records = [{"Data": b"control", "PartitionKey": "pk-control"} for _ in range(3)]
    control_resp = c.put_records(StreamName=name, Records=control_records)
    assert control_resp["FailedRecordCount"] == 0, (
        f"positive control: expected 0 failed records for a 3-record batch, "
        f"got {control_resp['FailedRecordCount']}"
    )

    landed_after_control = _poll(
        lambda: _read_records(c, name, shard_id),
        lambda recs: len(recs) >= 3,
        60, 2, f"3 control records visible on shard {shard_id}",
    )
    assert len(landed_after_control) == 3, (
        f"expected exactly 3 records after the control write, got {len(landed_after_control)}"
    )

    oversized_records = [{"Data": b"x", "PartitionKey": f"pk-{i}"} for i in range(501)]
    code, message = _error(lambda: c.put_records(StreamName=name, Records=oversized_records))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    # AWS echoes the rejected list as its server-side entry representation, in request order.
    entries = ", ".join(
        f"PutRecordsRequestEntry(data=java.nio.HeapByteBuffer[pos=0 lim={len(r['Data'])} "
        f"cap={len(r['Data'])}], explicitHashKey=null, partitionKey={r['PartitionKey']})"
        for r in oversized_records
    )
    expected_message = (
        f"1 validation error detected: Value '[{entries}]' at 'records' failed to satisfy "
        f"constraint: Member must have length less than or equal to 500"
    )
    assert message == expected_message, (
        f"501-record PutRecords message {message!r}, expected {expected_message!r}"
    )

    landed_after_rejection = _read_records(c, name, shard_id)
    assert len(landed_after_rejection) == 3, (
        f"a rejected 501-record PutRecords call must not land any records, but shard now has "
        f"{len(landed_after_rejection)} records (expected the 3 from the control write only)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
