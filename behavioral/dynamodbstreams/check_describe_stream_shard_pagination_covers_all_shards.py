"""describe-stream-shard-pagination-covers-all-shards."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-stream-shard-pagination-covers-all-shards"
GROUP = "pagination"
SERVICES = ["dynamodbstreams"]

_VIEW = "NEW_AND_OLD_IMAGES"


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStream with Limit=1 pages one shard at a time, its token is the last shard, and the
    final page omits it; the pages cover the full shard set once. ListStreams is scoped by table.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, _VIEW, "sim2real-behav-dbspage-")
    desc, shard_ids, _iterators = _wait_stream_usable(streams, stream_arn)

    assert desc["StreamArn"] == stream_arn, (
        f"DescribeStream must echo the ARN it was asked about, got {desc.get('StreamArn')!r}"
    )
    assert desc["TableName"] == table, (
        f"DescribeStream must name the source table, got {desc.get('TableName')!r}"
    )
    assert desc["StreamStatus"] == "ENABLED", (
        f"a stream that hands out iterators must report ENABLED, got "
        f"{desc.get('StreamStatus')!r}"
    )
    assert desc["StreamViewType"] == _VIEW, (
        f"StreamViewType must be {_VIEW}, got {desc.get('StreamViewType')!r}"
    )
    assert desc["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], (
        f"DescribeStream must echo the table key schema, got {desc.get('KeySchema')!r}"
    )
    assert stream_arn.endswith("/" + desc["StreamLabel"]), (
        f"the StreamLabel must be the trailing component of the stream ARN; label "
        f"{desc.get('StreamLabel')!r} vs arn {stream_arn!r}"
    )
    assert "LastEvaluatedShardId" not in desc, (
        f"an unlimited DescribeStream returned every shard, so it must not offer a page token; "
        f"got {desc.get('LastEvaluatedShardId')!r}"
    )
    # An OPEN shard has a StartingSequenceNumber and no EndingSequenceNumber.
    for shard in desc["Shards"]:
        rng = shard["SequenceNumberRange"]
        assert rng.get("StartingSequenceNumber", "").isdigit(), (
            f"every shard reports a numeric StartingSequenceNumber, got {rng!r}"
        )
        assert "EndingSequenceNumber" not in rng, (
            f"an OPEN shard has no EndingSequenceNumber; shard {shard['ShardId']} reported "
            f"{rng.get('EndingSequenceNumber')!r}"
        )

    # Bounded above the shard count so a token that never ends cannot loop forever.
    paged: list = []
    tokens: list = []
    start = None
    for _page in range(len(shard_ids) + 2):
        kwargs = {"StreamArn": stream_arn, "Limit": 1}
        if start is not None:
            kwargs["ExclusiveStartShardId"] = start
        page = streams.describe_stream(**kwargs)["StreamDescription"]
        ids = [s["ShardId"] for s in page.get("Shards", [])]
        assert len(ids) == 1, (
            f"Limit=1 must return exactly one shard per page, got {len(ids)}: {ids!r}"
        )
        paged += ids
        token = page.get("LastEvaluatedShardId")
        tokens.append(token)
        if token is None:
            break
        assert token == ids[0], (
            f"the page token must be the last shard on the page; page returned {ids!r} with "
            f"token {token!r}"
        )
        start = token

    assert tokens[-1] is None, (
        f"paging must terminate by omitting LastEvaluatedShardId; the last {len(tokens)} pages "
        f"produced tokens {tokens!r}"
    )
    assert len(paged) == len(set(paged)), (
        f"paging must not return a shard twice; the pages returned {paged!r}"
    )
    assert set(paged) == set(shard_ids), (
        f"paging with Limit=1 must cover exactly the shards the unpaginated call reported; "
        f"paged {sorted(paged)!r} vs full {sorted(shard_ids)!r}"
    )

    listed = _list_streams(streams, table)
    assert [s["StreamArn"] for s in listed] == [stream_arn], (
        f"ListStreams(TableName={table}) must report exactly this table's one stream, got "
        f"{[s.get('StreamArn') for s in listed]!r}"
    )
    assert listed[0]["TableName"] == table, (
        f"the ListStreams entry must name the table, got {listed[0]!r}"
    )
    assert listed[0]["StreamLabel"] == desc["StreamLabel"], (
        f"ListStreams and DescribeStream must agree on the StreamLabel; {listed[0]!r} vs "
        f"{desc['StreamLabel']!r}"
    )

    other = _list_streams(streams, table + "-absent")
    assert other == [], (
        f"ListStreams for a table that does not exist must report no streams, got {other!r}"
    )


def _list_streams(streams, table_name: str) -> list:
    """Every stream for one table, following LastEvaluatedStreamArn to the end.

    ListStreams exposes no paginator in botocore, hence the explicit next-token loop.
    """
    out: list = []
    start = None
    while True:
        kwargs = {"TableName": table_name}
        if start is not None:
            kwargs["ExclusiveStartStreamArn"] = start
        resp = streams.list_streams(**kwargs)
        out += resp.get("Streams", [])
        start = resp.get("LastEvaluatedStreamArn")
        if start is None:
            return out


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

    GetShardIterator can answer ResourceNotFoundException for a few seconds after the stream
    already reports ENABLED with shards.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
