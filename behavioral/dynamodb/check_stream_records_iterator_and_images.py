"""stream-records-iterator-and-images."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stream-records-iterator-and-images"
GROUP = 'streams'
SERVICES = ['dynamodb']

_VIEW_TYPE = 'NEW_AND_OLD_IMAGES'


def _poll(fn, pred, *, timeout_s, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f'{description} not met within {timeout_s}s. Last: {val!r}')
        time.sleep(interval_s)
        val = fn()
    return val


def _shard_ids(streams, stream_arn):
    desc = streams.describe_stream(StreamArn=stream_arn)['StreamDescription']
    return desc, [s['ShardId'] for s in desc.get('Shards', [])]


def _iterators(streams, stream_arn, shard_ids, iterator_type):
    """One shard iterator per shard, of the requested type."""
    return [
        streams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=sid, ShardIteratorType=iterator_type,
        )['ShardIterator']
        for sid in shard_ids
    ]


def _drain(streams, shard_ids, iterators, *, want, timeout_s):
    """Follow every shard's NextShardIterator chain until `want` records have been collected or
    the deadline passes.

    Returns (tagged, surviving_iterators) where `tagged` is a list of (shard_id, record) in
    per-shard arrival order -- GetRecords returns a shard's records in sequence order, and that is
    the ONLY order the service defines.

    A freshly enabled stream on an empty PAY_PER_REQUEST table can already have several shards,
    with mutations distributed across them by partition key, and sequence numbers are per-shard:
    records are kept shard-tagged so ordering is only asserted within a shard.
    """
    tagged: list[tuple[str, dict]] = []
    cursors = list(iterators)
    deadline = time.monotonic() + timeout_s
    while len(tagged) < want and time.monotonic() < deadline:
        progressed = False
        for i, cursor in enumerate(cursors):
            if cursor is None:
                continue
            resp = streams.get_records(ShardIterator=cursor)
            got = resp.get('Records', [])
            if got:
                tagged.extend((shard_ids[i], r) for r in got)
                progressed = True
            # A shard that is still OPEN must always hand back a NextShardIterator, even when
            # it returned zero records -- that is how a consumer keeps its place.
            cursors[i] = resp.get('NextShardIterator')
        if len(tagged) >= want:
            break
        if not progressed:
            time.sleep(2.0)
    return tagged, cursors


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """TRIM_HORIZON replays every mutation as one record in per-shard commit order with the right
    eventName, Keys and NEW_AND_OLD_IMAGES images, open shards always return a NextShardIterator,
    and a LATEST iterator taken after those mutations sees none of them but sees a later one."""
    ddb = ctx.client('dynamodb')
    streams = ctx.client('dynamodbstreams')

    t = ctx.unique_name('sim2real-behav-')
    created = ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        StreamSpecification={'StreamEnabled': True, 'StreamViewType': _VIEW_TYPE},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    stream_arn = created['TableDescription']['LatestStreamArn']
    assert stream_arn and ':table/' in stream_arn and '/stream/' in stream_arn, (
        f'CreateTable with StreamEnabled must mint a LatestStreamArn of the form '
        f'arn:...:table/<name>/stream/<label>, got {stream_arn!r}'
    )
    described_table = ddb.describe_table(TableName=t)['Table']
    assert described_table['LatestStreamArn'] == stream_arn, (
        f'DescribeTable must echo the same LatestStreamArn, got '
        f'{described_table.get("LatestStreamArn")} vs {stream_arn}'
    )
    assert described_table['StreamSpecification'] == {'StreamEnabled': True, 'StreamViewType': _VIEW_TYPE}, (
        f'DescribeTable must echo the stream specification, got {described_table.get("StreamSpecification")}'
    )

    # --- ListStreams surfaces the stream for this table ---
    listed = streams.list_streams(TableName=t)['Streams']
    assert any(s['StreamArn'] == stream_arn for s in listed), (
        f'ListStreams(TableName={t}) must include {stream_arn}, got {listed}'
    )
    entry = next(s for s in listed if s['StreamArn'] == stream_arn)
    assert entry.get('TableName') == t, f'the ListStreams entry must name the table, got {entry}'

    # --- DescribeStream exposes the stream's shape and at least one shard ---
    desc, shard_ids = _poll(
        lambda: _shard_ids(streams, stream_arn),
        lambda r: bool(r[1]),
        timeout_s=120,
        description='DescribeStream reports at least one shard',
    )
    assert desc['StreamStatus'] in ('ENABLING', 'ENABLED'), (
        f'a freshly enabled stream must be ENABLING or ENABLED, got {desc.get("StreamStatus")}'
    )
    assert desc['StreamViewType'] == _VIEW_TYPE, (
        f'StreamViewType must be {_VIEW_TYPE}, got {desc.get("StreamViewType")}'
    )
    assert desc['StreamArn'] == stream_arn, f'StreamArn mismatch: {desc.get("StreamArn")}'
    assert desc['TableName'] == t, f'DescribeStream must name the table, got {desc.get("TableName")}'
    assert desc['KeySchema'] == [{'AttributeName': 'pk', 'KeyType': 'HASH'}], (
        f'DescribeStream must echo the table key schema, got {desc.get("KeySchema")}'
    )

    # --- three mutations of one item: INSERT, MODIFY, REMOVE ---
    key = {'pk': {'S': 's1'}}
    ddb.put_item(TableName=t, Item={**key, 'v': {'N': '1'}})
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET v = :v',
        ExpressionAttributeValues={':v': {'N': '2'}},
    )
    ddb.delete_item(TableName=t, Key=key)

    # --- TRIM_HORIZON replays all three, in commit order ---
    horizon = _iterators(streams, stream_arn, shard_ids, 'TRIM_HORIZON')
    tagged, _ = _drain(streams, shard_ids, horizon, want=3, timeout_s=180)
    records = [r for _sid, r in tagged]
    assert len(records) == 3, (
        f'TRIM_HORIZON must replay exactly the 3 mutations from the start of the shard, got '
        f'{len(records)}: {[r.get("eventName") for r in records]}'
    )
    # All three mutations touch ONE item, and DynamoDB's ordering guarantee is per partition key:
    # they must therefore all be delivered on the SAME shard. This is what makes the commit-order
    # assertion below meaningful -- across shards there is no defined order at all -- and it is a
    # real constraint on a multi-shard stream.
    history_shards = {sid for sid, _r in tagged}
    assert len(history_shards) == 1, (
        f'every mutation to a single partition key must land on one shard, so that a consumer sees '
        f'them in order; the 3 mutations to s1 were spread over {sorted(history_shards)}'
    )
    history_shard = history_shards.pop()

    assert [r['eventName'] for r in records] == ['INSERT', 'MODIFY', 'REMOVE'], (
        f'one record per mutation, in commit order, with the mutation-specific eventName; got '
        f'{[r["eventName"] for r in records]}'
    )
    for r in records:
        assert r['eventSource'] == 'aws:dynamodb', f'eventSource must be aws:dynamodb, got {r}'
        assert r['dynamodb']['Keys'] == key, (
            f'every stream record must carry the item Keys regardless of view type, got '
            f'{r["dynamodb"].get("Keys")}'
        )
        assert r['dynamodb']['StreamViewType'] == _VIEW_TYPE, (
            f'each record must report its StreamViewType, got {r["dynamodb"].get("StreamViewType")}'
        )
        assert 'ApproximateCreationDateTime' in r['dynamodb'], (
            f'each record must carry ApproximateCreationDateTime, got members '
            f'{sorted(r["dynamodb"])}'
        )

    insert, modify, remove = records
    assert insert['dynamodb']['NewImage'] == {**key, 'v': {'N': '1'}}, (
        f'INSERT must carry the full NewImage, got {insert["dynamodb"].get("NewImage")}'
    )
    assert 'OldImage' not in insert['dynamodb'], (
        f'INSERT has no prior image, so OldImage must be absent, got {insert["dynamodb"].get("OldImage")}'
    )
    assert modify['dynamodb']['OldImage'] == {**key, 'v': {'N': '1'}}, (
        f'MODIFY must carry the pre-update OldImage, got {modify["dynamodb"].get("OldImage")}'
    )
    assert modify['dynamodb']['NewImage'] == {**key, 'v': {'N': '2'}}, (
        f'MODIFY must carry the post-update NewImage, got {modify["dynamodb"].get("NewImage")}'
    )
    assert remove['dynamodb']['OldImage'] == {**key, 'v': {'N': '2'}}, (
        f'REMOVE must carry the deleted item as OldImage, got {remove["dynamodb"].get("OldImage")}'
    )
    assert 'NewImage' not in remove['dynamodb'], (
        f'REMOVE has no resulting image, so NewImage must be absent, got {remove["dynamodb"].get("NewImage")}'
    )

    # Within one shard -- established above -- sequence numbers are ordered and comparable.
    seqs = [int(r['dynamodb']['SequenceNumber']) for r in records]
    assert seqs == sorted(seqs) and len(set(seqs)) == 3, (
        f'SequenceNumbers must be distinct and monotonically increasing with commit order, got {seqs}'
    )
    shard_start = {
        s['ShardId']: int(s['SequenceNumberRange']['StartingSequenceNumber'])
        for s in desc['Shards']
    }
    assert seqs[0] > shard_start[history_shard], (
        f'a record must sequence after its own shard\'s StartingSequenceNumber '
        f'({shard_start[history_shard]}), got {seqs[0]}'
    )

    # --- LATEST must NOT replay history ---
    latest = _iterators(streams, stream_arn, shard_ids, 'LATEST')
    first_poll = [streams.get_records(ShardIterator=it) for it in latest]
    for resp in first_poll:
        assert resp.get('Records') == [], (
            f'a LATEST iterator taken after the mutations must see none of them; got '
            f'{[r.get("eventName") for r in resp.get("Records", [])]}'
        )
        assert resp.get('NextShardIterator'), (
            'GetRecords on an open shard must return a NextShardIterator even with zero records'
        )
    cursors = [resp['NextShardIterator'] for resp in first_poll]

    # --- but it DOES see a mutation made after it was taken ---
    # A DIFFERENT partition key, so this also measures the fan-out: the record may be delivered on
    # any shard, and the LATEST iterators are followed on all of them.
    ddb.put_item(TableName=t, Item={'pk': {'S': 's2'}, 'v': {'N': '9'}})
    tail, cursors = _drain(streams, shard_ids, cursors, want=1, timeout_s=180)
    assert len(tail) == 1, (
        f'the LATEST-anchored iterator must deliver exactly the one post-anchor mutation, got '
        f'{[r.get("eventName") for _s, r in tail]}'
    )
    tail_shard, tail_record = tail[0]
    assert tail_record['eventName'] == 'INSERT', tail_record
    assert tail_record['dynamodb']['Keys'] == {'pk': {'S': 's2'}}, (
        f'the LATEST iterator must not replay the s1 history, got '
        f'{tail_record["dynamodb"].get("Keys")}'
    )
    # Deliberately NOT compared against seqs[-1]: this record may be on another shard, and sequence
    # numbers are only ordered within a shard. It is compared against its OWN shard's start, which
    # is the strongest statement the service's contract supports.
    assert int(tail_record['dynamodb']['SequenceNumber']) > shard_start[tail_shard], (
        f'the post-anchor record must sequence after its own shard\'s start '
        f'({shard_start[tail_shard]}), got {tail_record["dynamodb"]["SequenceNumber"]}'
    )

    # Ordering is guaranteed only within a shard: another mutation to the ORIGINAL key must arrive on the SAME shard as the
    # replayed history and must sequence after all of it.
    ddb.put_item(TableName=t, Item={**key, 'v': {'N': '7'}})
    resumed, _ = _drain(streams, shard_ids, cursors, want=1, timeout_s=180)
    assert len(resumed) == 1, (
        f'a further mutation to the original key must be delivered exactly once, got '
        f'{[(s, r.get("eventName")) for s, r in resumed]}'
    )
    resumed_shard, resumed_record = resumed[0]
    assert resumed_shard == history_shard, (
        f'a mutation to the same partition key must stay on the shard that carried its history, '
        f'got {resumed_shard} vs {history_shard}'
    )
    assert resumed_record['dynamodb']['Keys'] == key, (
        f'expected the s1 record, got {resumed_record["dynamodb"].get("Keys")}'
    )
    assert int(resumed_record['dynamodb']['SequenceNumber']) > seqs[-1], (
        f'within a shard, a later mutation must sequence after the earlier ones, got '
        f'{resumed_record["dynamodb"]["SequenceNumber"]} vs {seqs[-1]}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
