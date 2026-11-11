"""disable-closes-shards-and-reenable-mints-new-stream."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-closes-shards-and-reenable-mints-new-stream"
GROUP = "lifecycle"
SERVICES = ["dynamodbstreams"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling a stream closes its shards but keeps it readable; re-enabling mints a new ARN.

    The old stream stays DISABLED with its view type and records; ListStreams reports both, and
    the deleted table is refused with the exact not-found messages.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table, first_arn = _create_stream_table(
        ctx, ddb, "NEW_AND_OLD_IMAGES", "sim2real-behav-dbslife-")
    _desc, shard_ids, horizon = _wait_stream_usable(streams, first_arn)

    key = {"pk": {"S": "lifecycle-item"}}
    ddb.put_item(TableName=table, Item={**key, "v": {"N": "1"}})
    tagged = _drain(streams, shard_ids, horizon, want=1)
    assert len(tagged) == 1, (
        f"the write must reach the stream before it is disabled; drained {len(tagged)} records"
    )
    written_shard, written_record = tagged[0]
    assert written_record["eventName"] == "INSERT", written_record

    ddb.update_table(TableName=table, StreamSpecification={"StreamEnabled": False})
    disabled = _poll(
        lambda: streams.describe_stream(StreamArn=first_arn)["StreamDescription"],
        lambda d: d["StreamStatus"] == "DISABLED",
        description="the stream reaches DISABLED",
    )
    assert disabled["StreamViewType"] == "NEW_AND_OLD_IMAGES", (
        f"a disabled stream keeps the view type it was created with, got "
        f"{disabled.get('StreamViewType')!r}"
    )
    assert {s["ShardId"] for s in disabled["Shards"]} == set(shard_ids), (
        f"disabling must not drop shards; had {sorted(shard_ids)!r}, now "
        f"{sorted(s['ShardId'] for s in disabled['Shards'])!r}"
    )
    for shard in disabled["Shards"]:
        rng = shard["SequenceNumberRange"]
        assert rng.get("EndingSequenceNumber", "").isdigit(), (
            f"every shard of a disabled stream must be CLOSED by an EndingSequenceNumber; shard "
            f"{shard['ShardId']} reported {rng!r}"
        )

    described = ddb.describe_table(TableName=table)["Table"]
    assert "StreamSpecification" not in described, (
        f"DescribeTable drops StreamSpecification once the stream is off, got "
        f"{described.get('StreamSpecification')!r}"
    )
    assert described["LatestStreamArn"] == first_arn, (
        f"LatestStreamArn keeps pointing at the disabled stream, got "
        f"{described.get('LatestStreamArn')!r}"
    )

    # The record written before the disable is still readable out of the closed shard.
    replayed = _drain(
        streams,
        [written_shard],
        [streams.get_shard_iterator(
            StreamArn=first_arn, ShardId=written_shard,
            ShardIteratorType="TRIM_HORIZON")["ShardIterator"]],
        want=1,
    )
    assert [r["dynamodb"]["Keys"] for _s, r in replayed] == [key], (
        f"a disabled stream's closed shard must still replay the records it holds, got "
        f"{[r['dynamodb'].get('Keys') for _s, r in replayed]!r}"
    )

    updated = ddb.update_table(
        TableName=table,
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"},
    )
    second_arn = updated["TableDescription"]["LatestStreamArn"]
    assert second_arn and second_arn != first_arn, (
        f"re-enabling must mint a NEW stream rather than revive the old one; got "
        f"{second_arn!r} against the original {first_arn!r}"
    )
    reenabled = _poll(
        lambda: streams.describe_stream(StreamArn=second_arn)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ENABLED",
        description="the new stream reaches ENABLED",
    )
    assert reenabled["StreamViewType"] == "KEYS_ONLY", (
        f"the new stream must carry the view type the re-enable asked for, got "
        f"{reenabled.get('StreamViewType')!r}"
    )
    assert streams.describe_stream(
        StreamArn=first_arn)["StreamDescription"]["StreamStatus"] == "DISABLED", (
        "the original stream must stay DISABLED after a new one is enabled"
    )

    both = {s["StreamArn"] for s in _list_streams(streams, table)}
    assert both == {first_arn, second_arn}, (
        f"ListStreams must report the disabled stream alongside the new one; got {sorted(both)!r}"
    )

    ddb.delete_table(TableName=table)
    _poll(
        lambda: _table_status(ddb, table),
        lambda st: st == "GONE",
        description="the parent table is deleted",
    )
    refused = _expect_error(lambda: ddb.describe_table(TableName=table),
                            ("ResourceNotFoundException",), contains=(table,))
    expected_message = f"Requested resource not found: Table: {table} not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    names = [n for page in ddb.get_paginator("list_tables").paginate()
             for n in page.get("TableNames", [])]
    assert table not in names, f"deleted table {table} still listed by ListTables"
    # AWS's item-level not-found message does not name the table.
    refused = _expect_error(lambda: ddb.put_item(TableName=table, Item={**key, "v": {"N": "2"}}),
                            ("ResourceNotFoundException",))
    expected_message = "Requested resource not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _table_status(ddb, name: str) -> str:
    try:
        return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_table_if_present(ddb, name: str) -> None:
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll(fn, pred, *, timeout_s: float = POLL_BUDGET_S, interval_s: float = 3.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


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
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, name))
    stream_arn = created["TableDescription"]["LatestStreamArn"]
    assert stream_arn, (
        f"CreateTable with StreamEnabled must mint a LatestStreamArn, got "
        f"{created['TableDescription'].get('LatestStreamArn')!r}"
    )
    return name, stream_arn


def _wait_stream_usable(streams, stream_arn: str, timeout_s: float = POLL_BUDGET_S):
    """Poll until DescribeStream reports shards AND every shard hands back an iterator.

    GetShardIterator can answer ResourceNotFoundException for a few seconds after DescribeStream
    already reports ENABLED with shards.
    """
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
