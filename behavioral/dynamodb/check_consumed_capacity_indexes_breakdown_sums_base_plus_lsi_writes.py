"""consumed-capacity-indexes-breakdown-sums-base-plus-lsi-writes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "consumed-capacity-indexes-breakdown-sums-base-plus-lsi-writes"
GROUP = 'limits'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With ReturnConsumedCapacity=INDEXES, a sub-1KB write into two LSIs bills 3.0 (1.0 table
    plus 1.0 per LSI entry) and the breakdown sums to the total; a write into no LSI bills 1.0
    with no per-index share."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
            {'AttributeName': 'li1', 'AttributeType': 'S'},
            {'AttributeName': 'li2', 'AttributeType': 'S'},
        ],
        LocalSecondaryIndexes=[
            {'IndexName': 'lsi1',
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li1', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': 'lsi2',
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li2', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Both index range keys present, so both LSI entries are written.
    both = ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'a'}, 'sk': {'N': '1'}, 'li1': {'S': 'x'}, 'li2': {'S': 'y'}},
        ReturnConsumedCapacity='INDEXES',
    )
    cc = both.get('ConsumedCapacity') or {}
    assert cc.get('TableName') == t, f'ConsumedCapacity must name the table, got {cc.get("TableName")!r}'
    assert cc.get('CapacityUnits') == 3.0, (
        f'two-LSI write must bill 3.0 total (1 base + 2 index entries), got {cc.get("CapacityUnits")!r}'
    )
    assert (cc.get('Table') or {}).get('CapacityUnits') == 1.0, (
        f'base-table share must be 1.0, got {(cc.get("Table") or {}).get("CapacityUnits")!r}'
    )
    per_index = cc.get('LocalSecondaryIndexes') or {}
    assert set(per_index) == {'lsi1', 'lsi2'}, f'expected a per-LSI breakdown for both indexes, got {sorted(per_index)}'
    for name in ('lsi1', 'lsi2'):
        assert per_index[name].get('CapacityUnits') == 1.0, (
            f'{name} share must be 1.0, got {per_index[name].get("CapacityUnits")!r}'
        )
    assert cc['Table']['CapacityUnits'] + sum(v['CapacityUnits'] for v in per_index.values()) == cc['CapacityUnits'], (
        f'breakdown must sum to the aggregate: {cc!r}'
    )

    # Omitting both index range keys writes no index entry, so only the base table bills.
    neither = ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'b'}, 'sk': {'N': '2'}},
        ReturnConsumedCapacity='INDEXES',
    )
    cc2 = neither.get('ConsumedCapacity') or {}
    assert cc2.get('CapacityUnits') == 1.0, (
        f'write projecting into no LSI must bill 1.0, got {cc2.get("CapacityUnits")!r}'
    )
    assert not (cc2.get('LocalSecondaryIndexes') or {}), (
        f'no LSI entry was written, so no per-index share may be reported, got {cc2.get("LocalSecondaryIndexes")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
