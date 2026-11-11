"""deep-dynamodb-2-set-list-index-out-of-bounds-appends."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-set-list-index-out-of-bounds-appends"
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
        assert set(el) == {'S'}, f'list element is not a plain string (padding?): {el!r} in {attr!r}'
        out.append(el['S'])
    return out


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """SET l[99] on a 5-element list appends at the end, with no error and no null padding.

    Two out-of-bounds indices in one expression append in ascending index order:
    `SET l[99] = X, l[98] = Y` yields [..., Y, X].
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)

    ddb.put_item(TableName=t, Item={'pk': {'S': 'one'}, 'l': _slist(['a', 'b', 'c', 'd', 'e'])})
    resp = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'one'}},
        UpdateExpression='SET l[99] = :v',
        ExpressionAttributeValues={':v': {'S': 'X'}},
        ReturnValues='ALL_NEW',
    )
    returned = _strings(resp['Attributes']['l'])
    assert returned == ['a', 'b', 'c', 'd', 'e', 'X'], (
        f'ALL_NEW after SET l[99] was {returned!r}; expected X appended at the end'
    )
    stored = _strings(_stored(ddb, t, 'one')['l'])
    assert len(stored) == 6, f'stored list length {len(stored)} after out-of-bounds SET; expected 6: {stored!r}'
    assert stored == ['a', 'b', 'c', 'd', 'e', 'X'], (
        f'stored list after SET l[99] was {stored!r}; expected [a, b, c, d, e, X]'
    )

    # The appended element is now addressable at index 5, not 99.
    got = ddb.get_item(
        TableName=t, Key={'pk': {'S': 'one'}}, ConsistentRead=True,
        ProjectionExpression='l[5], l[99]',
    )['Item']
    assert got == {'l': {'L': [{'S': 'X'}]}}, (
        f'projection l[5], l[99] returned {got!r}; expected only l[5] = X (nothing lives at 99)'
    )

    # Two out-of-bounds indices in one expression: appended in ascending index order.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'two'}, 'l': _slist(['a', 'b', 'c', 'd', 'e'])})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'two'}},
        UpdateExpression='SET l[99] = :x, l[98] = :y',
        ExpressionAttributeValues={':x': {'S': 'X'}, ':y': {'S': 'Y'}},
    )
    stored = _strings(_stored(ddb, t, 'two')['l'])
    assert stored == ['a', 'b', 'c', 'd', 'e', 'Y', 'X'], (
        f'stored list after SET l[99]=X, l[98]=Y was {stored!r}; expected [a, b, c, d, e, Y, X] '
        f'(appends ordered by index, not by clause order)'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
