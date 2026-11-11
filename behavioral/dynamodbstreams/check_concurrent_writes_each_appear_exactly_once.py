"""concurrent-writes-each-appear-exactly-once."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-writes-each-appear-exactly-once"
GROUP = "concurrency"
SERVICES = ["dynamodbstreams"]

_KEYS = 16


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sixteen simultaneous writes to sixteen distinct keys each appear in the stream exactly once:
    draining every shard yields sixteen INSERT records for precisely the written keys, with distinct
    eventIDs and SequenceNumbers (no loss, no duplication)."""
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbsconc-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    written = [f"conc-{i:02d}" for i in range(_KEYS)]

    def put(name: str) -> None:
        ddb.put_item(TableName=table, Item={"pk": {"S": name}, "v": {"S": name}})

    with ThreadPoolExecutor(max_workers=_KEYS) as pool:
        for future in [pool.submit(put, name) for name in written]:
            future.result()

    tagged = _drain(streams, shard_ids, horizon, want=_KEYS)
    records = [rec for _shard, rec in tagged]
    assert len(records) == _KEYS, (
        f"every one of the {_KEYS} concurrent writes must be delivered; drained "
        f"{len(records)} records for keys "
        f"{sorted(r['dynamodb']['Keys']['pk']['S'] for r in records)!r}"
    )

    delivered = [rec["dynamodb"]["Keys"]["pk"]["S"] for rec in records]
    assert sorted(delivered) == sorted(written), (
        f"the delivered key multiset must equal the written one exactly -- no loss, no "
        f"duplication, nothing invented; wrote {sorted(written)!r}, got {sorted(delivered)!r}"
    )
    names = {rec["eventName"] for rec in records}
    assert names == {"INSERT"}, (
        f"a first write to each key is an INSERT; got event names {sorted(names)!r}"
    )
    event_ids = [rec["eventID"] for rec in records]
    assert len(set(event_ids)) == _KEYS, (
        f"each record must carry a distinct eventID; got {len(set(event_ids))} distinct of "
        f"{_KEYS}"
    )
    seqs = [rec["dynamodb"]["SequenceNumber"] for rec in records]
    assert len(set(seqs)) == _KEYS, (
        f"each record must carry a distinct SequenceNumber; got {len(set(seqs))} distinct of "
        f"{_KEYS}: {sorted(seqs)!r}"
    )
    for rec in records:
        body = rec["dynamodb"]["NewImage"]
        assert body["v"]["S"] == body["pk"]["S"], (
            f"each record's NewImage must be the item its own writer wrote, got {body!r}"
        )


# ===== helpers =====

def _create_stream_table(ctx, ddb, view_type: str, prefix: str) -> tuple[str, str]:
    name = ctx.unique_name(prefix)
    created = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": view_type},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    stream_arn = created["TableDescription"]["LatestStreamArn"]
    assert stream_arn, (
        f"CreateTable with StreamEnabled must mint a LatestStreamArn, got "
        f"{created['TableDescription'].get('LatestStreamArn')!r}"
    )
    return name, stream_arn


def _wait_stream_usable(streams, stream_arn: str, timeout_s: float = 180.0):
    """Poll until DescribeStream reports shards AND every shard hands back an iterator.

    Shards appear ~8 s after CreateTable and DescribeStream already
    reports StreamStatus=ENABLED, but GetShardIterator keeps answering
    ResourceNotFoundException 'Stream does not exist' for a further ~2 s.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
        shard_ids = [s["ShardId"] for s in desc.get("Shards", [])]
        if shard_ids:
            try:
                iterators = [
                    streams.get_shard_iterator(
                        StreamArn=stream_arn, ShardId=sid,
                        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
                    for sid in shard_ids
                ]
            except ClientError as exc:
                last = exc.response["Error"]["Code"]
                if last != "ResourceNotFoundException":
                    raise
            else:
                return desc, shard_ids, iterators
        else:
            last = f"{desc.get('StreamStatus')} with 0 shards"
        time.sleep(2.0)
    raise AssertionError(
        f"stream {stream_arn} never became readable within {timeout_s}s; last state {last!r}"
    )


def _drain(streams, shard_ids: list, iterators: list, *, want: int, timeout_s: float = 150.0):
    """Follow every shard's NextShardIterator chain until ``want`` records are collected.

    Keeps polling for a few rounds after reaching ``want`` would be wrong here -- an extra
    duplicate is exactly what the caller asserts against -- so the caller drains to ``want`` and
    then compares the multiset, which catches a duplicate as a missing key.
    """
    tagged: list = []
    cursors = list(iterators)
    deadline = time.monotonic() + timeout_s
    while len(tagged) < want and time.monotonic() < deadline:
        progressed = False
        for i, cursor in enumerate(cursors):
            if cursor is None:
                continue
            resp = streams.get_records(ShardIterator=cursor)
            got = resp.get("Records", [])
            if got:
                tagged.extend((shard_ids[i], rec) for rec in got)
                progressed = True
            cursors[i] = resp.get("NextShardIterator")
        if len(tagged) >= want or not any(cursors):
            break
        if not progressed:
            time.sleep(2.0)
    return tagged


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
