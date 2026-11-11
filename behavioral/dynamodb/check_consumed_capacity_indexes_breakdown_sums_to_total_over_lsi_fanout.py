"""consumed-capacity-indexes-breakdown-sums-to-total-over-lsi-fanout."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "consumed-capacity-indexes-breakdown-sums-to-total-over-lsi-fanout"
GROUP = 'expressions'
SERVICES = ['dynamodb']

_LSI1 = 'lsi1'
_LSI2 = 'lsi2'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReturnConsumedCapacity=INDEXES bills 1.0 WCU per LSI entry written, itemizes only touched
    indexes, and the itemized breakdown sums to the total across writes supplying both, one, or no
    LSI keys.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-lsicc-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': n, 'AttributeType': 'S'}
                              for n in ('pk', 'sk', 'l1', 'l2')],
        BillingMode='PAY_PER_REQUEST',
        LocalSecondaryIndexes=[
            {'IndexName': _LSI1,
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                           {'AttributeName': 'l1', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': _LSI2,
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                           {'AttributeName': 'l2', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
        ],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def _put(key, extra):
        item = {'pk': {'S': key}, 'sk': {'S': 'only'}}
        item.update(extra)
        resp = ddb.put_item(TableName=t, Item=item, ReturnConsumedCapacity='INDEXES')
        cc = resp.get('ConsumedCapacity')
        assert cc is not None, (
            f'ReturnConsumedCapacity=INDEXES must return ConsumedCapacity for the {key!r} write, '
            f'got response members {sorted(resp)!r}'
        )
        return cc

    both = _put('both', {'l1': {'S': 'a'}, 'l2': {'S': 'b'}})
    one = _put('one', {'l1': {'S': 'a'}})
    none = _put('none', {})

    assert both.get('CapacityUnits') == 3.0, (
        f'a <=1KB write supplying both LSI range keys writes 3 index entries (base + 2 LSIs) and '
        f'must bill exactly 3.0 WCU, got {both.get("CapacityUnits")!r}'
    )
    assert one.get('CapacityUnits') == 2.0, (
        f'a <=1KB write supplying one LSI range key writes 2 index entries and must bill exactly '
        f'2.0 WCU, got {one.get("CapacityUnits")!r}'
    )
    assert none.get('CapacityUnits') == 1.0, (
        f'a <=1KB write supplying no LSI range key writes only the base item and must bill exactly '
        f'1.0 WCU, got {none.get("CapacityUnits")!r}'
    )

    # An LSI fan-out never re-charges the base item.
    for label, cc in (('both', both), ('one', one), ('none', none)):
        assert cc.get('Table', {}).get('CapacityUnits') == 1.0, (
            f'the {label!r} write stores exactly one base item and must itemize the base table at '
            f'1.0 WCU, got Table={cc.get("Table")!r}'
        )

    assert sorted(both.get('LocalSecondaryIndexes', {})) == [_LSI1, _LSI2], (
        f'a write supplying both LSI range keys must itemize both indexes under '
        f'LocalSecondaryIndexes, got {sorted(both.get("LocalSecondaryIndexes", {}))!r}'
    )
    for name in (_LSI1, _LSI2):
        assert both['LocalSecondaryIndexes'][name].get('CapacityUnits') == 1.0, (
            f'each LSI entry written costs exactly 1.0 WCU; {name} reported '
            f'{both["LocalSecondaryIndexes"][name]!r}'
        )
    assert sorted(one.get('LocalSecondaryIndexes', {})) == [_LSI1], (
        f'a write supplying only the {_LSI1} range key must itemize {_LSI1} and nothing else, got '
        f'{sorted(one.get("LocalSecondaryIndexes", {}))!r}'
    )
    assert 'LocalSecondaryIndexes' not in none, (
        f'a write that creates no index entry must carry NO per-index breakdown member, got '
        f'{none.get("LocalSecondaryIndexes")!r}'
    )

    for label, cc in (('both', both), ('one', one), ('none', none)):
        parts = cc['Table']['CapacityUnits'] + sum(
            m['CapacityUnits'] for m in cc.get('LocalSecondaryIndexes', {}).values())
        assert parts == cc['CapacityUnits'], (
            f'the {label!r} write reported an itemized breakdown summing to {parts!r} against an '
            f'aggregate CapacityUnits of {cc["CapacityUnits"]!r}; the two must agree'
        )
    assert none['CapacityUnits'] < one['CapacityUnits'] < both['CapacityUnits'], (
        f'each additional index entry must cost exactly one more unit; got none='
        f'{none["CapacityUnits"]!r} one={one["CapacityUnits"]!r} both={both["CapacityUnits"]!r}'
    )

    for key in ('both', 'one', 'none'):
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}, 'sk': {'S': 'only'}},
                           ConsistentRead=True)
        assert got.get('Item', {}).get('pk') == {'S': key}, (
            f'the billed {key!r} write must be readable, so the capacity above was charged for real '
            f'work; got {got.get("Item")!r}'
        )
    idx = ddb.query(TableName=t, IndexName=_LSI1, KeyConditionExpression='pk = :p',
                    ExpressionAttributeValues={':p': {'S': 'both'}}, ConsistentRead=True)
    assert idx['Count'] == 1, (
        f'the 1.0 WCU billed against {_LSI1} must correspond to a real index entry, but querying '
        f'{_LSI1} returned {idx["Count"]!r} items: {idx.get("Items")!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
