"""put-item-overwrite-consumed-capacity-follows-larger-item-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-overwrite-consumed-capacity-follows-larger-item-image"
GROUP = 'capacity'
SERVICES = ['dynamodb']

# Item size rule (attribute name bytes + value bytes, summed): pk('pk'+'k')=3, blob('blob'+5600)=5604
# -> 5607 B total -> ceil(5607/1024) = 6 write units. blob('blob'+900) -> 907 B total -> 1 write unit.
BIG = 'x' * 5600
SMALL = 'y' * 900
SMALL2 = 'z' * 900


def _table(ctx, ddb) -> str:
    name = ctx.unique_name('sim2real-behav-')
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
    """A PutItem that overwrites a ~5.5 KB item with a ~0.9 KB one is charged for the larger,
    pre-write image; once both images are ~0.9 KB the charge drops to 1 WCU.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    key = {'pk': {'S': 'k'}}

    create = ddb.put_item(
        TableName=t, Item={'pk': {'S': 'k'}, 'blob': {'S': BIG}},
        ReturnConsumedCapacity='TOTAL',
    )
    u = _units(create, 'PutItem creating the ~5.6 KB item')
    assert u == 6.0, f'PutItem of a 5607-byte item with no prior image consumed {u!r} WCU; expected 6.0'

    created = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item') or {}
    assert created.get('blob', {}).get('S') == BIG, 'the created item must read back whole before the overwrite'

    overwrite = ddb.put_item(
        TableName=t, Item={'pk': {'S': 'k'}, 'blob': {'S': SMALL}},
        ReturnConsumedCapacity='TOTAL',
    )
    u = _units(overwrite, 'PutItem overwriting the ~5.6 KB item with a ~0.9 KB one')
    assert u == 6.0, (
        f'PutItem overwriting a 5607-byte item with a 907-byte one consumed {u!r} WCU; expected '
        f'6.0 (the larger, pre-write image). 1.0 means it was metered on the post-write size alone.'
    )

    shrunk = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item') or {}
    assert shrunk.get('blob', {}).get('S') == SMALL, 'the overwrite must persist the smaller image'

    same_size = ddb.put_item(
        TableName=t, Item={'pk': {'S': 'k'}, 'blob': {'S': SMALL2}},
        ReturnConsumedCapacity='TOTAL',
    )
    u = _units(same_size, 'PutItem overwriting a ~0.9 KB item with another ~0.9 KB one')
    assert u == 1.0, (
        f'PutItem overwriting a 907-byte item with another 907-byte one consumed {u!r} WCU; expected 1.0'
    )

    final = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item') or {}
    assert final.get('blob', {}).get('S') == SMALL2, 'the second overwrite must persist its own image'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
