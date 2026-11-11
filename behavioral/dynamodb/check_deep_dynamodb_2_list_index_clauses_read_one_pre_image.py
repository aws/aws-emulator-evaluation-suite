"""deep-dynamodb-2-list-index-clauses-read-one-pre-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-list-index-clauses-read-one-pre-image"
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
    """List-index clauses in one expression read and address the PRE-update list.

    `SET l[0] = l[1], l[1] = l[0]` swaps ([b,a,c,d,e]); `REMOVE l[0] SET l[1] = :v` replaces
    original index 1 and removes original index 0 ([X,c,d,e]).
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    five = ['a', 'b', 'c', 'd', 'e']

    ddb.put_item(TableName=t, Item={'pk': {'S': 'swap'}, 'l': _slist(five)})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'swap'}},
        UpdateExpression='SET l[0] = l[1], l[1] = l[0]',
    )
    swapped = _strings(_stored(ddb, t, 'swap')['l'])
    assert swapped == ['b', 'a', 'c', 'd', 'e'], (
        f'SET l[0] = l[1], l[1] = l[0] stored {swapped!r}; expected a swap [b, a, c, d, e]. '
        f'[b, b, ...] means the second clause read the already-updated l[0].'
    )

    ddb.put_item(TableName=t, Item={'pk': {'S': 'mixed'}, 'l': _slist(five)})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'mixed'}},
        UpdateExpression='REMOVE l[0] SET l[1] = :v',
        ExpressionAttributeValues={':v': {'S': 'X'}},
    )
    mixed = _strings(_stored(ddb, t, 'mixed')['l'])
    assert mixed == ['X', 'c', 'd', 'e'], (
        f'REMOVE l[0] SET l[1] = :v stored {mixed!r}; expected [X, c, d, e] '
        f'(original b replaced, original a removed). [b, X, d, e] means REMOVE shifted first.'
    )

    # A RHS reading a list element sees the pre-image even when the same list is rewritten.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'read'}, 'l': _slist(five)})
    ddb.update_item(
        TableName=t, Key={'pk': {'S': 'read'}},
        UpdateExpression='SET l = list_append(:z, l), last_seen = l[4]',
        ExpressionAttributeValues={':z': _slist(['Z'])},
    )
    item = _stored(ddb, t, 'read')
    assert item.get('last_seen') == {'S': 'e'}, (
        f'last_seen = l[4] stored {item.get("last_seen")!r}; expected the pre-image element e '
        f'(d would mean it read the list after the prepend)'
    )
    assert _strings(item['l']) == ['Z', 'a', 'b', 'c', 'd', 'e'], f'list after prepend: {item["l"]!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
