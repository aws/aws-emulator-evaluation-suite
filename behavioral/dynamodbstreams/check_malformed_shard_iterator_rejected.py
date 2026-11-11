"""malformed-shard-iterator-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "malformed-shard-iterator-rejected"
GROUP = "rejection"
SERVICES = ["dynamodbstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecords rejects an arbitrary string and a truncated real iterator with ValidationException
    'Invalid ShardIterator', and the rejections leave the intact iterator able to replay the record.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, stream_arn = _create_stream_table(ctx, ddb, "NEW_IMAGE", "sim2real-behav-dbsiterr-")
    _desc, shard_ids, _iterators = _wait_stream_usable(streams, stream_arn)

    key = {"pk": {"S": "iterator-item"}}
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "1"}})

    # The shard that actually carries the record, and an iterator onto it that stays untouched
    # while the malformed ones are rejected.
    holder, intact = _shard_holding_record(streams, stream_arn, shard_ids, key)

    code, message = _error(lambda: streams.get_records(
        ShardIterator="sim2real-behav-not-an-iterator"))
    # AWS answers ValidationException here although the Smithy model does not list it for GetRecords.
    assert code == "ValidationException", (
        f"GetRecords with an arbitrary string as the iterator must be ValidationException, got "
        f"{code!r}"
    )
    assert message == "Invalid ShardIterator", (
        f"GetRecords with an arbitrary string as the iterator answered message {message!r}"
    )

    truncated = intact[:-10]
    code, message = _error(lambda: streams.get_records(ShardIterator=truncated))
    assert code == "ValidationException", (
        f"GetRecords with a truncated copy of a real iterator must be ValidationException, got "
        f"{code!r}"
    )
    assert message == "Invalid ShardIterator", (
        f"GetRecords with a truncated copy of a real iterator answered message {message!r}"
    )

    # Effect absent: neither rejection consumed or invalidated the caller's real position.
    replayed = _drain(streams, [holder], [intact], want=1)
    assert [rec["dynamodb"]["Keys"] for _s, rec in replayed] == [key], (
        f"the intact iterator must still replay the record after the rejected calls, got "
        f"{[rec['dynamodb'].get('Keys') for _s, rec in replayed]!r}"
    )

    # Positive control: a freshly issued iterator on the same shard is accepted and reads the
    # same record, so the operation itself is healthy.
    fresh = streams.get_shard_iterator(
        StreamArn=stream_arn, ShardId=holder,
        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    control = _drain(streams, [holder], [fresh], want=1)
    assert [rec["dynamodb"]["NewImage"]["v"]["N"] for _s, rec in control] == ["1"], (
        f"the control iterator must read the written record, got "
        f"{[rec['dynamodb'].get('NewImage') for _s, rec in control]!r}"
    )


def _shard_holding_record(streams, stream_arn: str, shard_ids: list, key: dict,
                          timeout_s: float = 150.0) -> tuple[str, str]:
    """(shard_id, a fresh TRIM_HORIZON iterator) for the shard that carries ``key``'s record.

    Which shard a partition key lands on is not knowable in advance -- a freshly enabled stream
    may have several -- so this polls every shard until one delivers the record, then returns a
    NEW iterator onto that shard so the caller's position is untouched.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for sid in shard_ids:
            cursor = streams.get_shard_iterator(
                StreamArn=stream_arn, ShardId=sid,
                ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
            for record in streams.get_records(ShardIterator=cursor).get("Records", []):
                if record["dynamodb"]["Keys"] == key:
                    return sid, streams.get_shard_iterator(
                        StreamArn=stream_arn, ShardId=sid,
                        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        time.sleep(2.0)
    raise AssertionError(
        f"no shard of {stream_arn} delivered a record for {key!r} within {timeout_s}s"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) a call raised. Raises if the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
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


def _drain(streams, shard_ids: list, iterators: list, *, want: int, timeout_s: float = 120.0):
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
