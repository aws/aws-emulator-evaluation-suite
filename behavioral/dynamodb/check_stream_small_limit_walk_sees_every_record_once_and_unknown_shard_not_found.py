"""stream-small-limit-walk-sees-every-record-once-and-unknown-shard-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-small-limit-walk-sees-every-record-once-and-unknown-shard-not-found"
GROUP = "streams"
SERVICES = ["dynamodb"]

_KEYS = [f"k{i}" for i in range(8)]
_LIMIT = 2
_UNKNOWN_SHARD = "shardId-00000000000000000000-00000000"
_UNKNOWN_SHARD_MESSAGE = "Requested resource not found: Shard does not exist"


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _shards(streams, arn):
    shards, start = [], None
    while True:
        kwargs = {"StreamArn": arn}
        if start:
            kwargs["ExclusiveStartShardId"] = start
        desc = streams.describe_stream(**kwargs)["StreamDescription"]
        shards.extend(s["ShardId"] for s in desc.get("Shards", []))
        start = desc.get("LastEvaluatedShardId")
        if not start:
            return shards


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Walking every stream shard with GetRecords Limit=2 returns pages of at most 2 that together
    carry each of 8 inserts exactly once; GetShardIterator for an unknown shard is not found.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetRecords.html
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")
    table = ctx.unique_name("sim2real-behav-ddb-strwalk-")
    created = ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"},
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    arn = created["TableDescription"]["LatestStreamArn"]

    for key in _KEYS:
        ddb.put_item(TableName=table, Item={"pk": {"S": key}})

    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    cursors = {}
    records, oversized = [], []
    while time.monotonic() < deadline:
        for shard in _shards(streams, arn):
            if shard not in cursors:
                cursors[shard] = streams.get_shard_iterator(
                    StreamArn=arn, ShardId=shard, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        for shard, cursor in list(cursors.items()):
            if cursor is None:
                continue
            page = streams.get_records(ShardIterator=cursor, Limit=_LIMIT)
            got = page.get("Records", [])
            if len(got) > _LIMIT:
                oversized.append(len(got))
            records.extend(got)
            cursors[shard] = page.get("NextShardIterator")
        if len(records) >= len(_KEYS):
            break
        time.sleep(2)
    # Drain each shard to an empty page so a repeated record after the eighth is seen too.
    for shard, cursor in list(cursors.items()):
        while cursor is not None and time.monotonic() < deadline:
            page = streams.get_records(ShardIterator=cursor, Limit=_LIMIT)
            got = page.get("Records", [])
            if len(got) > _LIMIT:
                oversized.append(len(got))
            records.extend(got)
            cursor = page.get("NextShardIterator")
            if not got:
                break
    assert cursors, f"the stream {arn} never listed a shard"
    assert oversized == [], f"GetRecords with Limit={_LIMIT} returned pages of {oversized!r} records"

    event_ids = [r["eventID"] for r in records]
    assert len(event_ids) == len(set(event_ids)), f"the walk saw a record twice: {event_ids!r}"
    keys = sorted(r["dynamodb"]["Keys"]["pk"]["S"] for r in records)
    assert keys == _KEYS, f"the walk saw keys {keys!r}, expected each of {_KEYS!r} once"
    names = sorted({r["eventName"] for r in records})
    assert names == ["INSERT"], f"the walk saw event names {names!r}"

    code, msg = _error(lambda: streams.get_shard_iterator(
        StreamArn=arn, ShardId=_UNKNOWN_SHARD, ShardIteratorType="TRIM_HORIZON"))
    assert (code, msg) == ("ResourceNotFoundException", _UNKNOWN_SHARD_MESSAGE), (
        f"GetShardIterator for the unknown shard {_UNKNOWN_SHARD!r} gave {code!r}: {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
