"""shard-record-order-matches-write-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "shard-record-order-matches-write-order"
GROUP = "ordering"
SERVICES = ["dynamodbstreams"]

_WRITES = 12


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Twelve successive writes to one partition key land on one shard and are replayed by GetRecords
    in commit order with strictly increasing SequenceNumbers, and a second TRIM_HORIZON pass replays
    the identical order."""
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbsord-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "ordered-item"}}
    for n in range(1, _WRITES + 1):
        ddb.put_item(TableName=table, Item={**key, "v": {"N": str(n)}})

    tagged = _drain(streams, shard_ids, horizon, want=_WRITES)
    assert len(tagged) == _WRITES, (
        f"TRIM_HORIZON must replay all {_WRITES} writes to a single key; got {len(tagged)}: "
        f"{[r['dynamodb'].get('NewImage', {}).get('v', {}).get('N') for _s, r in tagged]!r}"
    )

    landed = {shard for shard, _rec in tagged}
    assert len(landed) == 1, (
        f"every write to one partition key must land on ONE shard so a consumer sees them in "
        f"order; the {_WRITES} writes were spread over {sorted(landed)!r}"
    )

    records = [rec for _shard, rec in tagged]
    values = [rec["dynamodb"]["NewImage"]["v"]["N"] for rec in records]
    assert values == [str(n) for n in range(1, _WRITES + 1)], (
        f"records must arrive in commit order 1..{_WRITES}; got {values!r}"
    )
    names = [rec["eventName"] for rec in records]
    assert names == ["INSERT"] + ["MODIFY"] * (_WRITES - 1), (
        f"the first write to a new key is INSERT and every overwrite is MODIFY; got {names!r}"
    )

    seqs = [int(rec["dynamodb"]["SequenceNumber"]) for rec in records]
    assert seqs == sorted(seqs) and len(set(seqs)) == _WRITES, (
        f"SequenceNumbers within a shard must be distinct and strictly increasing with commit "
        f"order; got {seqs!r}"
    )
    event_ids = [rec["eventID"] for rec in records]
    assert len(set(event_ids)) == _WRITES, (
        f"each record must carry a distinct eventID; got {len(set(event_ids))} distinct of "
        f"{_WRITES}: {event_ids!r}"
    )

    # Re-read the SAME shard from the horizon: the replay must be stable, not merely sorted once.
    replay_shard = landed.pop()
    second = _drain(
        streams,
        [replay_shard],
        [streams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=replay_shard,
            ShardIteratorType="TRIM_HORIZON")["ShardIterator"]],
        want=_WRITES,
    )
    second_values = [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in second]
    assert second_values == values, (
        f"a second TRIM_HORIZON pass over the same shard must replay the identical order; "
        f"first pass {values!r}, second pass {second_values!r}"
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    ResourceNotFoundException 'Stream does not exist' for a further ~2 s. Polling only
    DescribeStream is therefore not enough -- the observable condition is an iterator in hand.
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

    Returns [(shard_id, record)] in per-shard arrival order. Records are kept shard-tagged
    because GetRecords orders a SHARD's records and nothing orders records across shards.
    A fresh TRIM_HORIZON iterator's first GetRecords legitimately answers zero records
    (measured), so this polls a condition rather than trusting one call.
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
