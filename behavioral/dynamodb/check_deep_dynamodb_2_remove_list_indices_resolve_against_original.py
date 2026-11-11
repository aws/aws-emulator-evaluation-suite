"""deep-dynamodb-2-remove-list-indices-resolve-against-original."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-remove-list-indices-resolve-against-original"
GROUP = 'update-expression'
SERVICES = ['dynamodb']


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


def _slist(values):
    return {'L': [{'S': v} for v in values]}


def _strings(attr):
    assert set(attr) == {'L'}, f'expected a list attribute, got {attr!r}'
    out = []
    for el in attr['L']:
        assert set(el) == {'S'}, f'list element is not a plain string: {el!r} in {attr!r}'
        out.append(el['S'])
    return out


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """REMOVE l[1], l[2] in ONE expression removes the ORIGINAL elements 1 and 2: [a,d,e].

    The same removals as two calls compound to [a,c,e]; clause order is irrelevant
    (`REMOVE l[4], l[0]` -> [b,c,d]).
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    five = ['a', 'b', 'c', 'd', 'e']

    # One expression, two indices.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'single'}, 'l': _slist(five)})
    resp = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'single'}},
        UpdateExpression='REMOVE l[1], l[2]',
        ReturnValues='ALL_NEW',
    )
    returned = _strings(resp['Attributes']['l'])
    assert returned == ['a', 'd', 'e'], (
        f'ALL_NEW after REMOVE l[1], l[2] was {returned!r}; expected [a, d, e]'
    )
    single = _strings(_stored(ddb, t, 'single')['l'])
    assert single == ['a', 'd', 'e'], (
        f'stored list after REMOVE l[1], l[2] was {single!r}; expected [a, d, e] '
        f'(both indices against the original list). [a, c, e] means sequential removal.'
    )

    # Control: the same two removals as two separate calls DO compound.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'sequential'}, 'l': _slist(five)})
    ddb.update_item(TableName=t, Key={'pk': {'S': 'sequential'}}, UpdateExpression='REMOVE l[1]')
    ddb.update_item(TableName=t, Key={'pk': {'S': 'sequential'}}, UpdateExpression='REMOVE l[2]')
    sequential = _strings(_stored(ddb, t, 'sequential')['l'])
    assert sequential == ['a', 'c', 'e'], (
        f'two separate REMOVE calls (l[1] then l[2]) gave {sequential!r}; expected [a, c, e]'
    )
    assert single != sequential, (
        f'single-expression and sequential removal agree ({single!r}); they must differ'
    )

    # Clause order inside one expression does not matter.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'reversed'}, 'l': _slist(five)})
    ddb.update_item(TableName=t, Key={'pk': {'S': 'reversed'}}, UpdateExpression='REMOVE l[4], l[0]')
    rev = _strings(_stored(ddb, t, 'reversed')['l'])
    assert rev == ['b', 'c', 'd'], (
        f'stored list after REMOVE l[4], l[0] was {rev!r}; expected [b, c, d]'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
