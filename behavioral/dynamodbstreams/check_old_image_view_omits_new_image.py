"""old-image-view-omits-new-image."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "old-image-view-omits-new-image"
GROUP = "projection"
SERVICES = ["dynamodbstreams"]

_VIEW = "OLD_IMAGE"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An OLD_IMAGE stream projects only the pre-mutation item: INSERT carries no image, MODIFY and
    REMOVE carry the item as it stood before the write, and no record ever carries a NewImage."""
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, _VIEW, "sim2real-behav-dbsold-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "old-image-item"}}
    inserted = {**key, "v": {"N": "1"}, "note": {"S": "first"}}
    updated = {**key, "v": {"N": "2"}, "note": {"S": "first"}}
    ddb.put_item(TableName=table, Item=inserted)
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                    ExpressionAttributeValues={":v": {"N": "2"}})
    ddb.delete_item(TableName=table, Key=key)

    tagged = _drain(streams, shard_ids, horizon, want=3)
    records = [rec for _shard, rec in tagged]
    names = [rec["eventName"] for rec in records]
    assert names == ["INSERT", "MODIFY", "REMOVE"], (
        f"one record per mutation, in commit order, with the mutation-specific eventName; got "
        f"{names!r}"
    )
    insert, modify, remove = records

    assert "OldImage" not in insert["dynamodb"], (
        f"an INSERT has no prior item, so a {_VIEW} INSERT record must carry no OldImage; got "
        f"{insert['dynamodb'].get('OldImage')!r}"
    )
    assert modify["dynamodb"]["OldImage"] == inserted, (
        f"the MODIFY record's OldImage must be the item BEFORE the update, got "
        f"{modify['dynamodb'].get('OldImage')!r}"
    )
    assert remove["dynamodb"]["OldImage"] == updated, (
        f"the REMOVE record's OldImage must be the item as it stood at delete time, got "
        f"{remove['dynamodb'].get('OldImage')!r}"
    )

    for rec in records:
        payload = rec["dynamodb"]
        assert "NewImage" not in payload, (
            f"an {_VIEW} stream must never project a NewImage; the {rec['eventName']} record "
            f"carried {payload.get('NewImage')!r}"
        )
        assert payload["StreamViewType"] == _VIEW, (
            f"the {rec['eventName']} record must report StreamViewType {_VIEW}, got "
            f"{payload.get('StreamViewType')!r}"
        )
        assert payload["Keys"] == key, (
            f"every record carries the item Keys regardless of view type; the "
            f"{rec['eventName']} record carried {payload.get('Keys')!r}"
        )
        assert payload["SizeBytes"] > 0, (
            f"every record reports a positive SizeBytes; the {rec['eventName']} record reported "
            f"{payload.get('SizeBytes')!r}"
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
    described = ddb.describe_table(TableName=name)["Table"]
    assert described["StreamSpecification"] == {
        "StreamEnabled": True, "StreamViewType": view_type
    }, (
        f"DescribeTable must echo the stream specification, got "
        f"{described.get('StreamSpecification')!r}"
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
    """Follow every shard's NextShardIterator chain until ``want`` records are collected."""
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
