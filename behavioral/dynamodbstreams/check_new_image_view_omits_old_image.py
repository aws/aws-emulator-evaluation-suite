"""new-image-view-omits-old-image."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "new-image-view-omits-old-image"
GROUP = "projection"
SERVICES = ["dynamodbstreams"]

_VIEW = "NEW_IMAGE"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A NEW_IMAGE stream's INSERT and MODIFY records carry the item as it is after the write, no
    record carries an OldImage, and the REMOVE record carries neither image, only Keys.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, _VIEW, "sim2real-behav-dbsnew-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "new-image-item"}}
    inserted = {**key, "v": {"N": "1"}, "note": {"S": "first"}}
    updated = {**key, "v": {"N": "2"}, "note": {"S": "first"}}
    ddb.put_item(TableName=table, Item=inserted)
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                    ExpressionAttributeValues={":v": {"N": "2"}})
    ddb.delete_item(TableName=table, Key=key)

    # Independent confirmation that the delete actually took effect at the table -- a read
    # through a DIFFERENT operation than the mutation, and on the data plane the stream records
    # below are never asked to speak for.
    after_delete = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)
    assert "Item" not in after_delete, (
        f"after DeleteItem the item must be gone from the table; GetItem returned "
        f"{after_delete.get('Item')!r}"
    )

    tagged = _drain(streams, shard_ids, horizon, want=3)
    records = [rec for _shard, rec in tagged]
    names = [rec["eventName"] for rec in records]
    assert names == ["INSERT", "MODIFY", "REMOVE"], (
        f"one record per mutation, in commit order, with the mutation-specific eventName; got "
        f"{names!r}"
    )
    insert, modify, remove = records

    assert insert["dynamodb"]["NewImage"] == inserted, (
        f"the INSERT record's NewImage must be the item as written, got "
        f"{insert['dynamodb'].get('NewImage')!r}"
    )
    assert modify["dynamodb"]["NewImage"] == updated, (
        f"the MODIFY record's NewImage must be the item AFTER the update, got "
        f"{modify['dynamodb'].get('NewImage')!r}"
    )
    assert "NewImage" not in remove["dynamodb"], (
        f"a delete produces no resulting item, so a {_VIEW} REMOVE record must carry no "
        f"NewImage; got {remove['dynamodb'].get('NewImage')!r}"
    )

    for rec in records:
        payload = rec["dynamodb"]
        assert "OldImage" not in payload, (
            f"a {_VIEW} stream must never project an OldImage; the {rec['eventName']} record "
            f"carried {payload.get('OldImage')!r}"
        )
        assert payload["StreamViewType"] == _VIEW, (
            f"the {rec['eventName']} record must report StreamViewType {_VIEW}, got "
            f"{payload.get('StreamViewType')!r}"
        )
        assert payload["Keys"] == key, (
            f"every record carries the item Keys regardless of view type; the "
            f"{rec['eventName']} record carried {payload.get('Keys')!r}"
        )
        assert rec["eventVersion"] == "1.1", (
            f"the record format version must be 1.1, got {rec.get('eventVersion')!r}"
        )


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
    """Poll until DescribeStream lists shards AND every shard hands back an iterator.
    GetShardIterator can answer ResourceNotFoundException for a few seconds after ENABLED.
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
