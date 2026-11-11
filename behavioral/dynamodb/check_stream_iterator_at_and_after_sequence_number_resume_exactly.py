"""stream-iterator-at-and-after-sequence-number-resume-exactly."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stream-iterator-at-and-after-sequence-number-resume-exactly"
GROUP = 'streams'
SERVICES = ['dynamodb']

_VIEW_TYPE = 'NEW_AND_OLD_IMAGES'
_MUTATIONS = 5
_KEY = {'pk': {'S': 'checkpoint-subject'}}
_DRAIN_BUDGET_S = 180
_EMPTY_POLLS = 3


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


def _shard_ids(streams, stream_arn):
    desc = streams.describe_stream(StreamArn=stream_arn)['StreamDescription']
    return [s['ShardId'] for s in desc.get('Shards', [])]


def _iterator(streams, stream_arn, shard_id, iterator_type, sequence_number=None):
    kwargs = {'StreamArn': stream_arn, 'ShardId': shard_id,
              'ShardIteratorType': iterator_type}
    if sequence_number is not None:
        kwargs['SequenceNumber'] = sequence_number
    return streams.get_shard_iterator(**kwargs)['ShardIterator']


def _collect(streams, iterator, *, want, timeout_s, description):
    """Follow one shard's NextShardIterator chain until `want` records are collected.

    Raises on timeout or when the chain closes mid-stream.
    """
    got: list[dict] = []
    cursor = iterator
    deadline = time.monotonic() + timeout_s
    while len(got) < want:
        if cursor is None:
            raise AssertionError(
                f'{description}: the shard handed back a null NextShardIterator after '
                f'{len(got)!r} of {want!r} records, i.e. it closed mid-stream'
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'{description}: only {len(got)!r} of {want!r} records within {timeout_s!r}s; '
                f'sequence numbers so far '
                f'{[r["dynamodb"]["SequenceNumber"] for r in got]!r}'
            )
        resp = streams.get_records(ShardIterator=cursor)
        got += resp.get('Records', [])
        cursor = resp.get('NextShardIterator')
        if len(got) < want:
            time.sleep(2.0)
    return got, cursor


def _seqs(records):
    return [r['dynamodb']['SequenceNumber'] for r in records]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AT_SEQUENCE_NUMBER includes the checkpointed stream record and AFTER_SEQUENCE_NUMBER excludes
    it, so they differ by exactly that record; an iterator past the shard's end returns nothing
    until the next mutation, then delivers only that record.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetShardIterator.html
    """
    ddb = ctx.client('dynamodb')
    streams = ctx.client('dynamodbstreams')

    table = ctx.unique_name('sim2real-behav-ckpt-')
    created = ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        StreamSpecification={'StreamEnabled': True, 'StreamViewType': _VIEW_TYPE},
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'},
              {'Key': 'sim2real:check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    stream_arn = created['TableDescription']['LatestStreamArn']
    assert stream_arn, (
        f'CreateTable with StreamEnabled must mint a LatestStreamArn, got {stream_arn!r}'
    )

    shard_ids = _poll_until(
        lambda: _shard_ids(streams, stream_arn),
        bool,
        timeout_s=120,
        interval_s=3.0,
        description=f'DescribeStream({stream_arn}) to report at least one shard',
    )

    # Five mutations to ONE partition key: DynamoDB's ordering guarantee is per item, so these are
    # the only records whose relative order is defined -- and they must share a shard.
    for version in range(_MUTATIONS):
        ddb.put_item(TableName=table, Item={**_KEY, 'v': {'N': str(version)}})

    # A fresh stream can have several shards, so the one carrying this key is discovered.
    def _find_history_shard():
        for shard_id in shard_ids:
            cursor = _iterator(streams, stream_arn, shard_id, 'TRIM_HORIZON')
            if streams.get_records(ShardIterator=cursor).get('Records'):
                return shard_id
        return None

    history_shard = _poll_until(
        _find_history_shard,
        lambda s: s is not None,
        timeout_s=_DRAIN_BUDGET_S,
        interval_s=3.0,
        description=(
            f'one of the shards {shard_ids!r} to carry the {_MUTATIONS} mutations to '
            f'{_KEY!r}; without any delivery no checkpoint claim can be made'
        ),
    )
    baseline, _ = _collect(
        streams,
        _iterator(streams, stream_arn, history_shard, 'TRIM_HORIZON'),
        want=_MUTATIONS,
        timeout_s=_DRAIN_BUDGET_S,
        description=f'TRIM_HORIZON replay of shard {history_shard}',
    )
    assert len(baseline) == _MUTATIONS, (
        f'the shard carrying this key must replay exactly the {_MUTATIONS!r} mutations from the '
        f'horizon, got {len(baseline)!r}: {[r.get("eventName") for r in baseline]!r}'
    )
    for record in baseline:
        assert record['dynamodb']['Keys'] == _KEY, (
            f'every record on this shard must be for the single key under test; got '
            f'{record["dynamodb"].get("Keys")!r} -- the five mutations were spread over shards and '
            f'nothing below is comparable'
        )
    baseline_seqs = _seqs(baseline)
    assert len(set(baseline_seqs)) == _MUTATIONS, (
        f'sequence numbers within a shard must be distinct, got {baseline_seqs!r}'
    )
    assert [int(s) for s in baseline_seqs] == sorted(int(s) for s in baseline_seqs), (
        f'within one shard, sequence numbers must increase with commit order, got {baseline_seqs!r}'
    )
    checkpoint = baseline_seqs[2]

    at_records, _ = _collect(
        streams,
        _iterator(streams, stream_arn, history_shard, 'AT_SEQUENCE_NUMBER', checkpoint),
        want=_MUTATIONS - 2,
        timeout_s=_DRAIN_BUDGET_S,
        description=f'AT_SEQUENCE_NUMBER({checkpoint}) replay',
    )
    assert _seqs(at_records) == baseline_seqs[2:], (
        f'AT_SEQUENCE_NUMBER must start reading EXACTLY at the named record, so it must return the '
        f'checkpointed record and the two after it: expected {baseline_seqs[2:]!r}, got '
        f'{_seqs(at_records)!r}'
    )

    after_records, _ = _collect(
        streams,
        _iterator(streams, stream_arn, history_shard, 'AFTER_SEQUENCE_NUMBER', checkpoint),
        want=_MUTATIONS - 3,
        timeout_s=_DRAIN_BUDGET_S,
        description=f'AFTER_SEQUENCE_NUMBER({checkpoint}) replay',
    )
    assert _seqs(after_records) == baseline_seqs[3:], (
        f'AFTER_SEQUENCE_NUMBER must start reading RIGHT AFTER the named record, so the '
        f'checkpointed record itself must not reappear: expected {baseline_seqs[3:]!r}, got '
        f'{_seqs(after_records)!r}'
    )
    difference = [s for s in _seqs(at_records) if s not in _seqs(after_records)]
    assert difference == [checkpoint], (
        f'the inclusive and exclusive iterators taken at the same sequence number must differ by '
        f'precisely that one record: difference {difference!r}, expected {[checkpoint]!r} '
        f'(AT={_seqs(at_records)!r}, AFTER={_seqs(after_records)!r})'
    )

    # Nothing is trimmed within the 24h retention, so the first record is the horizon.
    from_first, _ = _collect(
        streams,
        _iterator(streams, stream_arn, history_shard, 'AT_SEQUENCE_NUMBER',
                  baseline_seqs[0]),
        want=_MUTATIONS,
        timeout_s=_DRAIN_BUDGET_S,
        description=f'AT_SEQUENCE_NUMBER({baseline_seqs[0]}) replay',
    )
    assert _seqs(from_first) == baseline_seqs, (
        f'AT_SEQUENCE_NUMBER at the shard\'s first record must reproduce the TRIM_HORIZON replay of '
        f'an untrimmed shard exactly: expected {baseline_seqs!r}, got {_seqs(from_first)!r}'
    )

    # The records were committed before this iterator was taken, so it excludes them by position.
    tail_cursor = _iterator(streams, stream_arn, history_shard, 'AFTER_SEQUENCE_NUMBER',
                            baseline_seqs[-1])
    for attempt in range(_EMPTY_POLLS):
        resp = streams.get_records(ShardIterator=tail_cursor)
        assert resp.get('Records') == [], (
            f'poll {attempt + 1!r}: an iterator positioned after the last committed record must not '
            f'replay history; it returned {_seqs(resp.get("Records", []))!r}, all of which are '
            f'already checkpointed ({baseline_seqs!r})'
        )
        assert resp.get('NextShardIterator'), (
            f'poll {attempt + 1!r}: GetRecords on an OPEN shard must hand back a NextShardIterator '
            f'even with zero records, or a consumer cannot keep its place; got '
            f'{resp.get("NextShardIterator")!r}'
        )
        tail_cursor = resp['NextShardIterator']

    ddb.delete_item(TableName=table, Key=_KEY)
    tail_records, _ = _collect(
        streams, tail_cursor, want=1, timeout_s=_DRAIN_BUDGET_S,
        description='the post-checkpoint REMOVE through the same iterator chain',
    )
    assert len(tail_records) == 1, (
        f'the chain must deliver exactly the one mutation committed after the checkpoint, got '
        f'{len(tail_records)!r}: {_seqs(tail_records)!r}'
    )
    tail = tail_records[0]
    assert tail['eventName'] == 'REMOVE', (
        f'the post-checkpoint mutation was a DeleteItem, so its record must be a REMOVE, got '
        f'{tail["eventName"]!r}'
    )
    assert tail['dynamodb']['SequenceNumber'] not in baseline_seqs, (
        f'the delivered record must be new, not a replay: {tail["dynamodb"]["SequenceNumber"]!r} is '
        f'one of the already-checkpointed {baseline_seqs!r}'
    )
    assert int(tail['dynamodb']['SequenceNumber']) > int(baseline_seqs[-1]), (
        f'within one shard a later mutation must sequence after the earlier ones: '
        f'{tail["dynamodb"]["SequenceNumber"]!r} vs {baseline_seqs[-1]!r}'
    )
    gone = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)
    assert 'Item' not in gone, (
        f'the REMOVE record must correspond to a real deletion; GetItem still returns '
        f'{gone.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
