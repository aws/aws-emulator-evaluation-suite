"""keys-only-view-omits-both-images."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "keys-only-view-omits-both-images"
GROUP = "projection"
SERVICES = ["dynamodbstreams"]

_VIEW = "KEYS_ONLY"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A KEYS_ONLY stream's INSERT, MODIFY and REMOVE records carry the exact Keys, no NewImage and
    no OldImage, and report KEYS_ONLY, for an item the table shows holds non-key attributes.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, _VIEW, "sim2real-behav-dbskeys-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "keys-only-item"}}
    body = {**key, "v": {"N": "1"}, "note": {"S": "projected-away"}}
    ddb.put_item(TableName=table, Item=body)

    # Control: the item genuinely holds non-key attributes, so their absence from the stream
    # records below is a projection decision and not an empty item.
    stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert stored == body, f"the table must hold the full item; GetItem returned {stored!r}"

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

    for rec in records:
        payload = rec["dynamodb"]
        assert payload["StreamViewType"] == _VIEW, (
            f"the {rec['eventName']} record must report StreamViewType {_VIEW}, got "
            f"{payload.get('StreamViewType')!r}"
        )
        assert payload["Keys"] == key, (
            f"the {rec['eventName']} record must carry exactly the item Keys, got "
            f"{payload.get('Keys')!r}"
        )
        assert "NewImage" not in payload, (
            f"a {_VIEW} stream must never project a NewImage; the {rec['eventName']} record "
            f"carried {payload.get('NewImage')!r}"
        )
        assert "OldImage" not in payload, (
            f"a {_VIEW} stream must never project an OldImage; the {rec['eventName']} record "
            f"carried {payload.get('OldImage')!r}"
        )
        for field in ("ApproximateCreationDateTime", "SequenceNumber", "SizeBytes"):
            assert field in payload, (
                f"every stream record carries {field} regardless of view type; the "
                f"{rec['eventName']} record held {sorted(payload)!r}"
            )
        assert rec["eventSource"] == "aws:dynamodb", (
            f"eventSource must be aws:dynamodb, got {rec.get('eventSource')!r}"
        )
        assert rec["awsRegion"] == ctx.region, (
            f"awsRegion must name the region the write happened in ({ctx.region}), got "
            f"{rec.get('awsRegion')!r}"
        )


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
