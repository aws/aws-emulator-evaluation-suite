"""deep-dynamodb-2-set-list-index-replaces-in-place."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-set-list-index-replaces-in-place"
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
    """SET l[0] on a 5-element list overwrites element 0 in place (returned and stored list stay 5 long), a second
    SET l[3] changes only element 3, and a nested path m[0][1] addresses the inner list's element.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)

    ddb.put_item(TableName=t, Item={'pk': {'S': 'flat'}, 'l': _slist(['a', 'b', 'c', 'd', 'e'])})
    resp = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'flat'}},
        UpdateExpression='SET l[0] = :v',
        ExpressionAttributeValues={':v': {'S': 'X'}},
        ReturnValues='ALL_NEW',
    )
    returned = _strings(resp['Attributes']['l'])
    assert returned == ['X', 'b', 'c', 'd', 'e'], (
        f'ALL_NEW after SET l[0] was {returned!r}; expected index 0 replaced in place'
    )
    stored = _strings(_stored(ddb, t, 'flat')['l'])
    assert stored == ['X', 'b', 'c', 'd', 'e'], (
        f'stored list after SET l[0] was {stored!r}; expected [X, b, c, d, e] (no insert, no shift)'
    )
    assert len(stored) == 5, f'list length changed from 5 to {len(stored)}: {stored!r}'

    # A middle index replaces only that element too.
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'flat'}},
        UpdateExpression='SET l[3] = :v',
        ExpressionAttributeValues={':v': {'S': 'Y'}},
    )
    stored = _strings(_stored(ddb, t, 'flat')['l'])
    assert stored == ['X', 'b', 'c', 'Y', 'e'], (
        f'stored list after SET l[3] was {stored!r}; expected [X, b, c, Y, e]'
    )

    # Nested list path: m[0][1] addresses the inner list.
    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'nested'},
        'm': {'L': [_slist(['p', 'q']), {'S': 'r'}]},
    })
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'nested'}},
        UpdateExpression='SET m[0][1] = :v',
        ExpressionAttributeValues={':v': {'S': 'Q'}},
    )
    m = _stored(ddb, t, 'nested')['m']
    assert m == {'L': [{'L': [{'S': 'p'}, {'S': 'Q'}]}, {'S': 'r'}]}, (
        f'stored nested list after SET m[0][1] was {m!r}; expected [[p, Q], r]'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
