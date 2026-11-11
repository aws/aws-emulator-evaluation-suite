"""kinesis-streaming-destination-delivers-item-change-records."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "kinesis-streaming-destination-delivers-item-change-records"
GROUP = 'streams'
SERVICES = ['dynamodb', 'kinesis']

_PRECISION = 'MICROSECOND'
_DELIVERY_BUDGET_S = 300
_STATUS_BUDGET_S = 600


_MANAGED_TAGS = [{'Key': 'sim2real:managed', 'Value': 'true'},
                 {'Key': 'sim2real:check', 'Value': CHECK}]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds. RAISES on timeout -- never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _create_stream(ctx) -> dict[str, Any]:
    kinesis = ctx.client('kinesis')
    name = ctx.unique_name('sim2real-xsvc-kin-')
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name,
                                                 EnforceConsumerDeletion=True))
    desc = _poll_until(
        lambda: kinesis.describe_stream(StreamName=name)['StreamDescription'],
        lambda d: d.get('StreamStatus') == 'ACTIVE',
        timeout_s=180, interval_s=3.0,
        description=f'Kinesis stream {name} to reach ACTIVE',
    )
    kinesis.add_tags_to_stream(StreamName=name,
                              Tags={t['Key']: t['Value'] for t in _MANAGED_TAGS})
    shard_id = desc['Shards'][0]['ShardId']
    return {'name': name, 'arn': desc['StreamARN'], 'shard_id': shard_id}


def _create_table(ctx) -> str:
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-xsvc-tbl-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _destination_status(ctx, table, stream_arn):
    described = ctx.client('dynamodb').describe_kinesis_streaming_destination(
        TableName=table)['KinesisDataStreamDestinations']
    for entry in described:
        if entry['StreamArn'] == stream_arn:
            return entry
    raise AssertionError(
        f'DescribeKinesisStreamingDestination({table}) does not mention {stream_arn}; it listed '
        f'{[e.get("StreamArn") for e in described]!r}'
    )


def _shard_iterator(ctx, stream, iterator_type='TRIM_HORIZON'):
    return ctx.client('kinesis').get_shard_iterator(
        StreamName=stream['name'], ShardId=stream['shard_id'],
        ShardIteratorType=iterator_type,
    )['ShardIterator']


def _pump(ctx, cursor, *, want, timeout_s, description):
    """Follow one Kinesis shard's iterator chain, decoding DynamoDB change records.

    Returns (records_by_event_id, next_cursor, last_response, seconds_to_first_record).
    RAISES on timeout: returning fewer records than asked for would let a target with no delivery
    path grade as merely slow.
    """
    kinesis = ctx.client('kinesis')
    collected: dict[str, dict] = {}
    first_seen_at = None
    started = time.monotonic()
    deadline = started + timeout_s
    last = None
    while len(collected) < want:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'{description}: {len(collected)!r} of {want!r} distinct change records within '
                f'{timeout_s!r}s; event names so far '
                f'{sorted(r.get("eventName") for r in collected.values())!r}'
            )
        last = kinesis.get_records(ShardIterator=cursor, Limit=100)
        for raw in last.get('Records', []):
            body = json.loads(raw['Data'].decode('utf-8'))
            event_id = body.get('eventID') or json.dumps(body, sort_keys=True)
            collected[event_id] = body
            if first_seen_at is None:
                first_seen_at = time.monotonic()
        cursor = last['NextShardIterator']
        if len(collected) < want:
            time.sleep(2.0)
    return collected, cursor, last, (first_seen_at or time.monotonic()) - started


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB Kinesis streaming destination delivers INSERT/MODIFY/REMOVE records with key and
    before/after images to GetRecords. Records are de-duplicated and compared as a set (no ordering).

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/kds.html
    """
    ddb = ctx.client('dynamodb')

    stream = _create_stream(ctx)
    table = _create_table(ctx)

    ddb.enable_kinesis_streaming_destination(
        TableName=table,
        StreamArn=stream['arn'],
        EnableKinesisStreamingConfiguration={
            'ApproximateCreationDateTimePrecision': _PRECISION,
        },
    )
    # Registered last so LIFO teardown disables the destination BEFORE the table and stream go.
    ctx.on_cleanup(lambda: ddb.disable_kinesis_streaming_destination(
        TableName=table, StreamArn=stream['arn']))

    active = _poll_until(
        lambda: _destination_status(ctx, table, stream['arn']),
        lambda e: e['DestinationStatus'] == 'ACTIVE',
        timeout_s=_STATUS_BUDGET_S, interval_s=10.0,
        description=f'the Kinesis destination on {table} to reach ACTIVE',
    )
    assert active.get('ApproximateCreationDateTimePrecision') == _PRECISION, (
        f'DescribeKinesisStreamingDestination must echo the configured timestamp precision '
        f'{_PRECISION!r}, got {active.get("ApproximateCreationDateTimePrecision")!r}'
    )

    cursor = _shard_iterator(ctx, stream)

    key = {'pk': {'S': 'cdc-subject'}}
    ddb.put_item(TableName=table, Item={**key, 'v': {'N': '1'}, 'note': {'S': 'created'}})
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression='SET v = :v, note = :n',
        ExpressionAttributeValues={':v': {'N': '2'}, ':n': {'S': 'updated'}},
    )
    ddb.delete_item(TableName=table, Key=key)

    delivered, cursor, _, _ = _pump(
        ctx, cursor, want=3, timeout_s=_DELIVERY_BUDGET_S,
        description=f'the three item changes on {table} to arrive in Kinesis stream {stream["name"]}',
    )

    # --- the terminal read is at the CONSUMER: what Kinesis handed us, not what DynamoDB said ---
    by_event = {}
    for body in delivered.values():
        assert body.get('tableName') == table, (
            f'every change record must name its source table {table!r}, got '
            f'{body.get("tableName")!r} in {sorted(body)!r}'
        )
        assert body.get('awsRegion') == ctx.region, (
            f'every change record must name the region it was produced in ({ctx.region!r}), got '
            f'{body.get("awsRegion")!r}'
        )
        payload = body['dynamodb']
        assert payload['Keys'] == key, (
            f'every change record must carry the changed item\'s primary key {key!r}, got '
            f'{payload.get("Keys")!r}'
        )
        assert payload.get('ApproximateCreationDateTime') is not None, (
            f'every change record must carry ApproximateCreationDateTime -- it is the only ordering '
            f'signal the service offers for this destination; members were {sorted(payload)!r}'
        )
        by_event.setdefault(body['eventName'], []).append(payload)

    assert set(by_event) == {'INSERT', 'MODIFY', 'REMOVE'}, (
        f'a PutItem, an UpdateItem and a DeleteItem on one item must produce one INSERT, one MODIFY '
        f'and one REMOVE change record; the stream delivered {sorted(by_event)!r} across '
        f'{len(delivered)!r} distinct eventIDs'
    )
    insert = by_event['INSERT'][0]
    modify = by_event['MODIFY'][0]
    remove = by_event['REMOVE'][0]
    assert insert['NewImage'] == {**key, 'v': {'N': '1'}, 'note': {'S': 'created'}}, (
        f'the INSERT record must carry the snapshot AFTER the modification, got '
        f'{insert.get("NewImage")!r}'
    )
    assert 'OldImage' not in insert, (
        f'an INSERT has no prior snapshot, so OldImage must be absent, got '
        f'{insert.get("OldImage")!r}'
    )
    assert modify['OldImage'] == {**key, 'v': {'N': '1'}, 'note': {'S': 'created'}}, (
        f'the MODIFY record must carry the snapshot BEFORE the modification, got '
        f'{modify.get("OldImage")!r}'
    )
    assert modify['NewImage'] == {**key, 'v': {'N': '2'}, 'note': {'S': 'updated'}}, (
        f'the MODIFY record must carry the snapshot AFTER the modification, got '
        f'{modify.get("NewImage")!r}'
    )
    assert remove['OldImage'] == {**key, 'v': {'N': '2'}, 'note': {'S': 'updated'}}, (
        f'the REMOVE record must carry the deleted item as its BEFORE snapshot, got '
        f'{remove.get("OldImage")!r}'
    )
    assert 'NewImage' not in remove, (
        f'a REMOVE leaves no snapshot after the modification, so NewImage must be absent, got '
        f'{remove.get("NewImage")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
