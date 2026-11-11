"""e2e-stream-produce-scale-consume-teardown."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-stream-produce-scale-consume-teardown"
GROUP = "e2e"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Records written before and after a SplitShard are all read back: pre-split ones from the
    closed parent, post-split ones from the two children. The stream is then deleted."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-splitflow-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))

    summary = _wait_stream_active(kinesis, stream_name)
    stream_arn = summary["StreamARN"]

    shards = kinesis.list_shards(StreamARN=stream_arn)["Shards"]
    assert len(shards) == 1, f"expected a 1-shard stream, ListShards gave {shards!r}"
    parent_shard = shards[0]
    parent_id = parent_shard["ShardId"]
    start = int(parent_shard["HashKeyRange"]["StartingHashKey"])
    end = int(parent_shard["HashKeyRange"]["EndingHashKey"])
    midpoint = start + (end - start) // 2
    assert start < midpoint <= end, (
        f"split midpoint {midpoint} is not strictly inside parent range [{start}, {end}]"
    )

    pre_split_payloads = [f"pre-split-{i}".encode() for i in range(5)]
    put_pre = kinesis.put_records(
        StreamARN=stream_arn,
        Records=[{"Data": p, "PartitionKey": f"pk-{i}"} for i, p in enumerate(pre_split_payloads)],
    )
    assert put_pre["FailedRecordCount"] == 0, (
        f"pre-split PutRecords had {put_pre['FailedRecordCount']} failures: {put_pre['Records']!r}"
    )

    kinesis.split_shard(
        StreamARN=stream_arn, ShardToSplit=parent_id, NewStartingHashKey=str(midpoint)
    )
    summary = _wait_stream_active(kinesis, stream_name)

    children = _wait_for_children(kinesis, stream_arn, parent_id)
    assert len(children) == 2, (
        f"split_shard produced {len(children)} children of {parent_id}, expected 2: {children!r}"
    )

    # ACTIVE after a reshard does not mean every hash-key route already points at the children;
    # wait (bounded) so the explicit-hash-key writes below land on a child, not the closed parent.
    _wait_for_settled_routing(kinesis, stream_arn, parent_id, children, start, end)

    # ExplicitHashKey at each end of the range exercises both children.
    low_payloads = [f"post-split-low-{i}".encode() for i in range(3)]
    high_payloads = [f"post-split-high-{i}".encode() for i in range(2)]
    records = [
        {"Data": p, "PartitionKey": "low", "ExplicitHashKey": str(start)} for p in low_payloads
    ] + [{"Data": p, "PartitionKey": "high", "ExplicitHashKey": str(end)} for p in high_payloads]
    put_post = kinesis.put_records(StreamARN=stream_arn, Records=records)
    assert put_post["FailedRecordCount"] == 0, (
        f"post-split PutRecords had {put_post['FailedRecordCount']} failures: {put_post['Records']!r}"
    )

    parent_records = _read_all_from_shard_until_match(
        kinesis, stream_arn, parent_id, expected_count=len(pre_split_payloads), closed=True
    )
    child_records: list[bytes] = []
    for child in children:
        child_records.extend(_read_all_from_shard(kinesis, stream_arn, child["ShardId"], closed=False))

    # drop the disposable settling-probe canaries emitted by _wait_for_settled_routing
    parent_records = [r for r in parent_records if not r.startswith(b"canary-")]
    child_records = [r for r in child_records if not r.startswith(b"canary-")]

    assert sorted(parent_records) == sorted(pre_split_payloads), (
        f"parent shard {parent_id} returned {parent_records!r}, expected {pre_split_payloads!r}"
    )
    assert sorted(child_records) == sorted(low_payloads + high_payloads), (
        f"child shards returned {child_records!r}, expected {sorted(low_payloads + high_payloads)!r}"
    )

    kinesis.delete_stream(StreamARN=stream_arn, EnforceConsumerDeletion=False)
    _poll_stream_deleted(kinesis, stream_arn)


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE, last={summary}")


def _wait_for_children(kinesis, stream_arn: str, parent_id: str, timeout_s: float = 120.0) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    children: list[dict] = []
    while time.monotonic() < deadline:
        all_shards = kinesis.list_shards(StreamARN=stream_arn)["Shards"]
        children = [s for s in all_shards if s.get("ParentShardId") == parent_id]
        if len(children) == 2:
            return children
        time.sleep(3)
    raise AssertionError(f"split_shard never produced 2 children for {parent_id}, got={children}")


def _wait_for_settled_routing(
    kinesis, stream_arn: str, parent_id: str, children: list[dict], start: int, end: int, timeout_s: float = 120.0
) -> None:
    """Probe with disposable canary records until explicit-hash-key writes at
    the two child boundary values stop landing on the closed parent shard --
    i.e. until the producer-side shard map has actually settled post-split."""
    deadline = time.monotonic() + timeout_s
    child_ids = {c["ShardId"] for c in children}
    while time.monotonic() < deadline:
        canary = kinesis.put_records(
            StreamARN=stream_arn,
            Records=[
                {"Data": b"canary-low", "PartitionKey": "low", "ExplicitHashKey": str(start)},
                {"Data": b"canary-high", "PartitionKey": "high", "ExplicitHashKey": str(end)},
            ],
        )
        landed_on_parent = any(
            r.get("ShardId") == parent_id for r in canary.get("Records", []) if "ShardId" in r
        )
        landed_on_children = all(
            r.get("ShardId") in child_ids for r in canary.get("Records", []) if "ShardId" in r
        )
        if not landed_on_parent and landed_on_children:
            return
        time.sleep(5)
    raise AssertionError(f"shard map for {parent_id} never settled onto children {child_ids}")


def _read_all_from_shard_until_match(
    kinesis, stream_arn: str, shard_id: str, expected_count: int, closed: bool, timeout_s: float = 90.0
) -> list[bytes]:
    deadline = time.monotonic() + timeout_s
    records: list[bytes] = []
    while time.monotonic() < deadline:
        records = _read_all_from_shard(kinesis, stream_arn, shard_id, closed=closed)
        if len(records) >= expected_count:
            return records
        time.sleep(3)
    return records


def _read_all_from_shard(
    kinesis, stream_arn: str, shard_id: str, timeout_s: float = 90.0, closed: bool = False
) -> list[bytes]:
    iterator = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    out: list[bytes] = []
    deadline = time.monotonic() + timeout_s
    consecutive_empty = 0
    while iterator is not None and time.monotonic() < deadline:
        resp = kinesis.get_records(StreamARN=stream_arn, ShardIterator=iterator, Limit=1000)
        if resp["Records"]:
            consecutive_empty = 0
            out.extend(bytes(r["Data"]) for r in resp["Records"])
        else:
            next_iterator = resp.get("NextShardIterator")
            if closed and next_iterator is None:
                # a CLOSED shard with no NextShardIterator has truly been
                # drained -- this is the authoritative end-of-shard signal
                break
            consecutive_empty += 1
            if not closed and consecutive_empty >= 10:
                # OPEN shard with no more data forthcoming after repeated polling
                break
            time.sleep(1)
        iterator = resp.get("NextShardIterator")
    return out


def _poll_stream_deleted(kinesis, stream_arn: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_summary(StreamARN=stream_arn)
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"stream {stream_arn} never finished deleting")


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if response is None:
        return None
    return response.get("Error", {}).get("Code")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
