"""nonexistent-stream-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "nonexistent-stream-arn-rejected"
GROUP = "rejection"
SERVICES = ["dynamodbstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeStream and GetShardIterator reject a well-formed stream ARN naming a missing table
    with ResourceNotFoundException (each with its own message), leave no stream or table behind,
    and the same two calls succeed on a real stream.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, "KEYS_ONLY", "sim2real-behav-dbsnf-")
    _desc, shard_ids, _iterators = _wait_stream_usable(streams, stream_arn)

    # The bogus ARN differs from the real one in the TABLE component and nothing else.
    absent_table = table + "-absent"
    label = stream_arn.rsplit("/", 1)[1]
    bogus_arn = (
        f"arn:aws:dynamodb:{ctx.region}:{stream_arn.split(':')[4]}:table/{absent_table}"
        f"/stream/{label}"
    )

    code, message = _error(lambda: streams.describe_stream(StreamArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"DescribeStream on a stream ARN whose table does not exist must be "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Requested resource not found: Stream: {bogus_arn} not found", (
        f"DescribeStream on a stream ARN whose table does not exist answered message {message!r}"
    )

    code, message = _error(lambda: streams.get_shard_iterator(
        StreamArn=bogus_arn, ShardId=shard_ids[0], ShardIteratorType="TRIM_HORIZON"))
    assert code == "ResourceNotFoundException", (
        f"GetShardIterator on a stream ARN whose table does not exist must be "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == "Requested resource not found: Stream does not exist", (
        f"GetShardIterator on a stream ARN whose table does not exist answered message "
        f"{message!r}"
    )

    # Effect absent: the rejected calls did not conjure a stream or a table.
    assert _list_streams(streams, absent_table) == [], (
        f"the rejected calls must leave no stream behind for {absent_table}"
    )
    code, message = _error(lambda: ddb.describe_table(TableName=absent_table))
    assert code == "ResourceNotFoundException", (
        f"the table named by the bogus ARN must still not exist, got {code!r}"
    )
    assert message == f"Requested resource not found: Table: {absent_table} not found", (
        f"DescribeTable on the table named by the bogus ARN answered message {message!r}"
    )

    # Positive control: the same two operations against the real stream.
    live = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
    assert live["StreamArn"] == stream_arn, (
        f"the control DescribeStream must answer for the real stream, got {live!r}"
    )
    iterator = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=shard_ids[0],
        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    assert iterator, "the control GetShardIterator must return a usable iterator"
    assert "Records" in streams.get_records(ShardIterator=iterator), (
        "the control iterator must be accepted by GetRecords"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) a call raised; raises if the call succeeds, so wrongful
    acceptance fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _list_streams(streams, table_name: str) -> list:
    """Every stream for one table, following LastEvaluatedStreamArn to the end."""
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

    GetShardIterator can answer ResourceNotFoundException for a few seconds after the stream
    reports ENABLED with shards, so a not-yet-ready stream must not pass for a missing one.
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
