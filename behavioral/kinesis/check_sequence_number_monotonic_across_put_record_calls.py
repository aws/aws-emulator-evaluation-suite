"""sequence-number-monotonic-across-put-record-calls."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sequence-number-monotonic-across-put-record-calls"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sequence numbers returned by successive PutRecord calls on one shard are strictly
    monotonically increasing, and GetRecords reflects the exact same sequence, in order."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-")
    _create_and_wait_stream(ctx, stream_name, shard_count=1)

    shards = _list_shards_when_ready(ctx, stream_name)
    assert len(shards) == 1, f"expected 1 shard, got {len(shards)}"
    shard_id = shards[0]["ShardId"]

    n = 12
    put_seqs = []
    for i in range(n):
        resp = kinesis.put_record(StreamName=stream_name, Data=f"m-{i}".encode(), PartitionKey="k")
        assert resp["ShardId"] == shard_id, (
            f"PutRecord {i} landed on shard {resp['ShardId']!r}, not the stream's only shard {shard_id!r}"
        )
        put_seqs.append(int(resp["SequenceNumber"]))

    assert all(put_seqs[i] < put_seqs[i + 1] for i in range(n - 1)), (
        f"PutRecord sequence numbers not strictly increasing: {put_seqs}"
    )

    fetched = _collect_records(ctx, stream_name, shard_id, expected_count=n)
    fetched_seqs = [int(r["SequenceNumber"]) for r in fetched]
    assert fetched_seqs == put_seqs, (
        f"GetRecords sequence order {fetched_seqs} does not match PutRecord call order {put_seqs}"
    )


def _create_and_wait_stream(ctx, stream_name: str, shard_count: int = 1, timeout_s: float = 300.0) -> str:
    kinesis = ctx.client("kinesis")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"},
    )
    _register_stream_teardown(ctx, kinesis, stream_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _register_stream_teardown(ctx, kinesis, stream_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    def _teardown():
        deadline = time.monotonic() + timeout_s
        last = None
        deleted = False
        while time.monotonic() < deadline:
            try:
                kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
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
                f"stream {stream_name} never reached a deletable state within {timeout_s}s "
                f"(last error {last}); it is still billing shard-hours"
            )
        while time.monotonic() < deadline:
            try:
                kinesis.describe_stream_summary(StreamName=stream_name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(interval_s)
        raise AssertionError(
            f"stream {stream_name} is still describable {timeout_s}s after DeleteStream returned; leak"
        )

    ctx.on_cleanup(_teardown)


def _list_shards_when_ready(ctx, stream_name: str, timeout_s: float = 60.0):
    """Even after describe_stream_summary reports ACTIVE, ListShards can briefly still
    raise ResourceInUseException while the stream finishes provisioning. Retry until it
    succeeds or the timeout elapses."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except kinesis.exceptions.ResourceInUseException as exc:
            last_err = exc
            time.sleep(2)
    raise AssertionError(f"ListShards kept raising ResourceInUseException for {stream_name} within {timeout_s}s: {last_err}")


def _collect_records(ctx, stream_name: str, shard_id: str, expected_count: int, timeout_s: float = 60.0):
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=1000)
        out.extend(resp["Records"])
        iterator = resp.get("NextShardIterator")
        if iterator is None:
            break
        if not resp["Records"]:
            time.sleep(1)
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} records, got {len(out)} within {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
