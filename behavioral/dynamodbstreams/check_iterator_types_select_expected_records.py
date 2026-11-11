"""iterator-types-select-expected-records."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "iterator-types-select-expected-records"
GROUP = "ordering"
SERVICES = ["dynamodbstreams"]

_WRITES = 5


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each ShardIteratorType selects an exact slice of five records: TRIM_HORIZON all, AT_SEQUENCE_NUMBER
    inclusive, AFTER_SEQUENCE_NUMBER exclusive, past-the-end none with a NextShardIterator, and LATEST
    none of the history but a later write.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbsiter-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "iter-item"}}
    for n in range(1, _WRITES + 1):
        ddb.put_item(TableName=table, Item={**key, "v": {"N": str(n)}})

    tagged = _drain(streams, shard_ids, horizon, want=_WRITES)
    assert len(tagged) == _WRITES, (
        f"TRIM_HORIZON must replay all {_WRITES} writes; got {len(tagged)}"
    )
    landed = {shard for shard, _rec in tagged}
    assert len(landed) == 1, (
        f"all writes to one key must land on one shard for these slices to be comparable; got "
        f"{sorted(landed)!r}"
    )
    shard = landed.pop()
    seqs = [rec["dynamodb"]["SequenceNumber"] for _s, rec in tagged]
    horizon_values = [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in tagged]
    assert horizon_values == ["1", "2", "3", "4", "5"], (
        f"TRIM_HORIZON must replay from the start of the shard in order; got {horizon_values!r}"
    )

    at_third = _read_slice(streams, stream_arn, shard, "AT_SEQUENCE_NUMBER", seqs[2], want=3)
    assert at_third == ["3", "4", "5"], (
        f"AT_SEQUENCE_NUMBER is inclusive of the named record, so it must return 3,4,5; got "
        f"{at_third!r}"
    )

    after_third = _read_slice(
        streams, stream_arn, shard, "AFTER_SEQUENCE_NUMBER", seqs[2], want=2)
    assert after_third == ["4", "5"], (
        f"AFTER_SEQUENCE_NUMBER is exclusive of the named record, so it must return 4,5; got "
        f"{after_third!r}"
    )

    past_end = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard,
        ShardIteratorType="AFTER_SEQUENCE_NUMBER", SequenceNumber=seqs[-1])["ShardIterator"]
    resp = streams.get_records(ShardIterator=past_end)
    assert resp.get("Records") == [], (
        f"AFTER the last record there is nothing left to read; got "
        f"{[r['dynamodb']['NewImage']['v']['N'] for r in resp.get('Records', [])]!r}"
    )
    assert resp.get("NextShardIterator"), (
        "an OPEN shard read past its end must still hand back a NextShardIterator so a consumer "
        f"keeps its place; response held {sorted(resp)!r}"
    )

    latest = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard, ShardIteratorType="LATEST")["ShardIterator"]
    first = streams.get_records(ShardIterator=latest)
    assert first.get("Records") == [], (
        f"a LATEST iterator taken after the history must see none of it; got "
        f"{[r['dynamodb']['NewImage']['v']['N'] for r in first.get('Records', [])]!r}"
    )
    assert first.get("NextShardIterator"), (
        f"GetRecords on an open shard must return a NextShardIterator even with zero records; "
        f"response held {sorted(first)!r}"
    )

    ddb.put_item(TableName=table, Item={**key, "v": {"N": "99"}})
    tail = _drain(streams, [shard], [first["NextShardIterator"]], want=1)
    tail_values = [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in tail]
    assert tail_values == ["99"], (
        f"the LATEST-anchored iterator must deliver the post-anchor write and nothing earlier; "
        f"got {tail_values!r}"
    )


def _read_slice(streams, stream_arn: str, shard: str, iterator_type: str,
                sequence_number: str, *, want: int) -> list:
    """The `v` values GetRecords yields for one iterator type anchored at one sequence number."""
    cursor = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard, ShardIteratorType=iterator_type,
        SequenceNumber=sequence_number)["ShardIterator"]
    return [rec["dynamodb"]["NewImage"]["v"]["N"]
            for _s, rec in _drain(streams, [shard], [cursor], want=want)]


def _create_stream_table(ctx, ddb, view_type: str, prefix: str) -> tuple[str, str]:
    name = ctx.unique_name(prefix)
    created = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": view_type},
        Tags=[{"Key": "simparity-check", "Value": "iterator-types-select-expected-records"}],
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

    GetShardIterator can answer ResourceNotFoundException for a few seconds after shards appear.
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

    A fresh iterator's first GetRecords can return zero records, so this polls.
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
