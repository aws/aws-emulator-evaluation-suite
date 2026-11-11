"""deep-dynamodb-2-remove-list-index-out-of-bounds-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-remove-list-index-out-of-bounds-is-noop"
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
    """REMOVE l[99] on a 5-element list succeeds and leaves the stored list unchanged (no clamping to the last
    element), while REMOVE l[99], l[0] in one expression removes only the first element.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)

    ddb.put_item(TableName=t, Item={'pk': {'S': 'k'}, 'l': _slist(['a', 'b', 'c', 'd', 'e'])})
    resp = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'k'}},
        UpdateExpression='REMOVE l[99]',
        ReturnValues='ALL_NEW',
    )
    assert resp['ResponseMetadata']['HTTPStatusCode'] == 200, f'REMOVE l[99] response: {resp!r}'
    stored = _strings(_stored(ddb, t, 'k')['l'])
    assert stored == ['a', 'b', 'c', 'd', 'e'], (
        f'stored list after REMOVE l[99] was {stored!r}; expected it unchanged [a, b, c, d, e]'
    )

    # Mixed with an in-bounds index: only the in-bounds removal applies.
    ddb.update_item(TableName=t, Key={'pk': {'S': 'k'}}, UpdateExpression='REMOVE l[99], l[0]')
    stored = _strings(_stored(ddb, t, 'k')['l'])
    assert stored == ['b', 'c', 'd', 'e'], (
        f'stored list after REMOVE l[99], l[0] was {stored!r}; expected [b, c, d, e]'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
