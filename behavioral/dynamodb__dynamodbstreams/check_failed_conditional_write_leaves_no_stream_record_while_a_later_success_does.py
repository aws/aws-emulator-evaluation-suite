"""failed-conditional-write-leaves-no-stream-record-while-a-later-success-does."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-conditional-write-leaves-no-stream-record-while-a-later-success-does"
GROUP = "streams"
SERVICES = ["dynamodb", "dynamodbstreams"]

_VIEW_TYPE = "NEW_AND_OLD_IMAGES"
_SHARDS_BUDGET_S = 60.0
_LATENCY_BUDGET_S = 60.0


def _error(fn):
    """The (Code, Message) fn() raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _shard_ids(streams, stream_arn):
    desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
    return [s["ShardId"] for s in desc.get("Shards", [])]


def _poll(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _drain(streams, cursors, *, until, interval_s=1.0):
    """(tagged, advanced_cursors): every record newly read from every open shard, tagged by shard,
    until until() first returns True, with each shard's cursor advanced past what was read."""
    tagged: list[tuple[str, dict]] = []
    cursors = dict(cursors)
    while True:
        progressed = False
        for shard_id, cursor in list(cursors.items()):
            if cursor is None:
                continue
            resp = streams.get_records(ShardIterator=cursor)
            got = resp.get("Records", [])
            if got:
                tagged.extend((shard_id, r) for r in got)
                progressed = True
            cursors[shard_id] = resp.get("NextShardIterator")
        if until(tagged):
            return tagged, cursors
        if not progressed:
            time.sleep(interval_s)


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A conditional UpdateItem that fails its condition produces no stream record for the
    attempted change, while an otherwise identical call that meets the condition does.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table = ctx.unique_name("sim2real-behav-condstream-")
    created = ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": _VIEW_TYPE},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    stream_arn = created["TableDescription"]["LatestStreamArn"]
    shard_ids = _poll(
        lambda: _shard_ids(streams, stream_arn),
        lambda ids: len(ids) > 0,
        timeout_s=_SHARDS_BUDGET_S,
        description="DescribeStream reporting at least one shard",
    )
    cursors = {
        sid: streams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=sid, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        for sid in shard_ids
    }

    # --- positive control: a plain write lands on the table and, measurably, on the stream ---
    write_started = time.monotonic()
    ddb.put_item(TableName=table, Item={"pk": {"S": "widget"}, "version": {"N": "1"}})
    first_batch, cursors = _drain(
        streams, cursors, until=lambda got: len(got) >= 1 or time.monotonic() - write_started > _LATENCY_BUDGET_S
    )
    assert len(first_batch) == 1, f"expected exactly one stream record after the PutItem, got {first_batch!r}"
    latency_s = time.monotonic() - write_started
    first_shard, first_record = first_batch[0]
    assert first_record["eventName"] == "INSERT", (
        f"the PutItem record's eventName was {first_record['eventName']!r}, expected 'INSERT'"
    )
    # --- break exactly one thing: a condition the current item does not satisfy ---
    code, message = _error(
        lambda: ddb.update_item(
            TableName=table,
            Key={"pk": {"S": "widget"}},
            UpdateExpression="SET version = :bad_new",
            ConditionExpression="version = :bad_cur",
            ExpressionAttributeValues={":bad_new": {"N": "97"}, ":bad_cur": {"N": "99"}},
        )
    )
    assert code == "ConditionalCheckFailedException", f"expected ConditionalCheckFailedException, got {code}"
    assert message == "The conditional request failed", f"unexpected message {message!r}"

    # --- the refused write is absent from the stream over a window derived from the measured
    # positive latency, not a single read or a fixed sleep ---
    window_s = max(10.0, 3.0 * latency_s)
    deadline = time.monotonic() + window_s
    absent_check, cursors = _drain(streams, cursors, until=lambda got: time.monotonic() >= deadline)
    assert absent_check == [], (
        f"the failed conditional UpdateItem produced {len(absent_check)} stream record(s), "
        f"expected none: {absent_check!r}"
    )

    # --- restore: the identical call, now satisfying its condition, succeeds and is recorded ---
    restore_started = time.monotonic()
    ddb.update_item(
        TableName=table,
        Key={"pk": {"S": "widget"}},
        UpdateExpression="SET version = :new",
        ConditionExpression="version = :cur",
        ExpressionAttributeValues={":new": {"N": "2"}, ":cur": {"N": "1"}},
    )
    second_batch, cursors = _drain(
        streams, cursors, until=lambda got: len(got) >= 1 or time.monotonic() - restore_started > _LATENCY_BUDGET_S
    )
    assert len(second_batch) == 1, f"expected exactly one stream record after the successful UpdateItem, got {second_batch!r}"
    second_shard, second_record = second_batch[0]
    assert second_record["eventName"] == "MODIFY", (
        f"the successful UpdateItem record's eventName was {second_record['eventName']!r}, expected 'MODIFY'"
    )
    assert second_record["dynamodb"]["NewImage"]["version"] == {"N": "2"}, (
        f"the MODIFY record's NewImage.version was {second_record['dynamodb']['NewImage'].get('version')!r}, "
        f"expected {{'N': '2'}}"
    )
    assert second_record["dynamodb"]["OldImage"]["version"] == {"N": "1"}, (
        f"the MODIFY record's OldImage.version was {second_record['dynamodb']['OldImage'].get('version')!r}, "
        f"expected {{'N': '1'}}, never the condition's rejected candidate"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
