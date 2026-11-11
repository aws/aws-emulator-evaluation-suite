"""update-max-record-size-enables-larger-put-record."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-max-record-size-enables-larger-put-record"
GROUP = "data-plane"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After UpdateMaxRecordSize raises a stream's limit, PutRecord accepts (and
    GetRecords faithfully returns) a payload that exceeds the default 1 MiB
    record-size limit, up to the new configured limit."""
    kinesis = ctx.client("kinesis")
    name, stream_arn = _create_active_stream(ctx)

    default_limit_bytes = 1024 * 1024  # documented default max record size is 1 MiB
    oversized_for_default = b"x" * (default_limit_bytes + 200 * 1024)  # ~1.2 MiB
    assert len(oversized_for_default) > default_limit_bytes, (
        f"test payload of {len(oversized_for_default)} bytes must exceed the "
        f"default limit of {default_limit_bytes} bytes"
    )

    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=3072)  # 3 MiB
    _wait_stream_active_by_arn(ctx, stream_arn)

    put_resp = kinesis.put_record(
        StreamARN=stream_arn, Data=oversized_for_default, PartitionKey="large-record"
    )
    assert put_resp["SequenceNumber"], f"PutRecord returned no SequenceNumber: {put_resp}"

    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records = _read_records(kinesis, iterator, 1, StreamARN=stream_arn)
    assert len(records) == 1, f"expected exactly 1 record on the shard, got {len(records)}"
    assert records[0]["Data"] == oversized_for_default, "round-tripped record data does not match what was put"
    assert records[0]["SequenceNumber"] == put_resp["SequenceNumber"], (
        f"expected the read-back SequenceNumber {put_resp['SequenceNumber']!r}, "
        f"got {records[0]['SequenceNumber']!r}"
    )


def _create_active_stream(ctx, shard_count: int = 1) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinesis-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=shard_count,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        last_status = desc["StreamStatus"]
        if last_status == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"stream never became ACTIVE (last status={last_status})")


def _wait_stream_active_by_arn(ctx, stream_arn: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
        last_status = desc["StreamStatus"]
        if last_status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream never returned to ACTIVE after UpdateMaxRecordSize (last status={last_status})")


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
