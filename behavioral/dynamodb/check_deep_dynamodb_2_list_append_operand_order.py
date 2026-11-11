"""deep-dynamodb-2-list-append-operand-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-list-append-operand-order"
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
    """list_append(#l, :v) appends and list_append(:v, #l) prepends, as the stored item shows after each update,
    and a multi-element operand keeps its own order: concatenation follows argument order.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    five = ['a', 'b', 'c', 'd', 'e']

    ddb.put_item(TableName=t, Item={'pk': {'S': 'append'}, 'l': _slist(five)})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'append'}},
        UpdateExpression='SET #l = list_append(#l, :v)',
        ExpressionAttributeNames={'#l': 'l'},
        ExpressionAttributeValues={':v': _slist(['Z'])},
    )
    appended = _strings(_stored(ddb, t, 'append')['l'])
    assert appended == ['a', 'b', 'c', 'd', 'e', 'Z'], (
        f'list_append(#l, :v) stored {appended!r}; expected Z at the END'
    )

    ddb.put_item(TableName=t, Item={'pk': {'S': 'prepend'}, 'l': _slist(five)})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'prepend'}},
        UpdateExpression='SET #l = list_append(:v, #l)',
        ExpressionAttributeNames={'#l': 'l'},
        ExpressionAttributeValues={':v': _slist(['Z'])},
    )
    prepended = _strings(_stored(ddb, t, 'prepend')['l'])
    assert prepended == ['Z', 'a', 'b', 'c', 'd', 'e'], (
        f'list_append(:v, #l) stored {prepended!r}; expected Z at the START'
    )
    assert appended != prepended, f'operand order had no effect: both gave {appended!r}'

    # Multi-element operand keeps its own internal order on both sides.
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'prepend'}},
        UpdateExpression='SET #l = list_append(:v, #l)',
        ExpressionAttributeNames={'#l': 'l'},
        ExpressionAttributeValues={':v': _slist(['P', 'Q'])},
    )
    both = _strings(_stored(ddb, t, 'prepend')['l'])
    assert both == ['P', 'Q', 'Z', 'a', 'b', 'c', 'd', 'e'], (
        f'prepending [P, Q] stored {both!r}; expected [P, Q, Z, a, b, c, d, e]'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
