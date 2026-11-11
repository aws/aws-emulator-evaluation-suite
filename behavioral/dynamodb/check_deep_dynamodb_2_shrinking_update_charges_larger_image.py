"""deep-dynamodb-2-shrinking-update-charges-larger-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-shrinking-update-charges-larger-image"
GROUP = 'capacity'
SERVICES = ['dynamodb']

# Item sizes per the DynamoDB item-size rules (UTF-8 attribute name bytes + value bytes):
#   pk('pk'+'k') = 3, big('big' + 5000) = 5003, small('small' + 900) = 905
#   full item = 5911 B -> ceil(5911 / 1024) = 6 write units
#   after REMOVE big = 908 B -> 1 write unit
BIG = 'x' * 5000
SMALL = 'y' * 900


def _table(ctx, ddb) -> str:
    name = ctx.unique_name('ddbexpr-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _units(resp, label):
    cc = resp.get('ConsumedCapacity')
    assert cc is not None, f'{label}: no ConsumedCapacity although ReturnConsumedCapacity was set: {resp!r}'
    return cc.get('CapacityUnits')


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """An UpdateItem that shrinks a ~6 KB item to ~1 KB is charged 6 WCU, the LARGER image.

    The next small update costs 1 WCU and growing it back costs 6: the charge is
    max(size before, size after). On-demand tables report CapacityUnits only.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    key = {'pk': {'S': 'k'}}

    put = ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'k'}, 'big': {'S': BIG}, 'small': {'S': SMALL}},
        ReturnConsumedCapacity='TOTAL',
    )
    u = _units(put, 'PutItem of the ~5.8 KB item')
    assert u == 6.0, f'PutItem of a 5911-byte item consumed {u!r} WCU; expected 6.0'

    shrink = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='REMOVE big',
        ReturnConsumedCapacity='INDEXES', ReturnValues='ALL_NEW',
    )
    assert set(shrink['Attributes']) == {'pk', 'small'}, f'shrink left {sorted(shrink["Attributes"])!r}'
    u = _units(shrink, 'shrinking UpdateItem')
    assert u == 6.0, (
        f'UpdateItem shrinking 5911 B -> 908 B consumed {u!r} WCU; expected 6.0 (the larger, '
        f'pre-update image). 1.0 means it was metered on the post-update size.'
    )
    table_units = shrink['ConsumedCapacity'].get('Table', {}).get('CapacityUnits')
    assert table_units == 6.0, f'INDEXES breakdown Table.CapacityUnits was {table_units!r}; expected 6.0'

    small = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET tick = :v',
        ExpressionAttributeValues={':v': {'N': '1'}}, ReturnConsumedCapacity='TOTAL',
    )
    u = _units(small, 'small update after shrink')
    assert u == 1.0, f'small update on the shrunken ~0.9 KB item consumed {u!r} WCU; expected 1.0'

    grow = ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET big = :b',
        ExpressionAttributeValues={':b': {'S': BIG}}, ReturnConsumedCapacity='TOTAL',
    )
    u = _units(grow, 'growing UpdateItem')
    assert u == 6.0, f'UpdateItem growing ~0.9 KB -> ~5.8 KB consumed {u!r} WCU; expected 6.0'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
