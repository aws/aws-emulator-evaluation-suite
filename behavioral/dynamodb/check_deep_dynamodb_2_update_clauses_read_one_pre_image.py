"""deep-dynamodb-2-update-clauses-read-one-pre-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-update-clauses-read-one-pre-image"
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


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """Every right-hand side of one UpdateExpression reads the same pre-image: from {a:1, b:2, c:3},
    `REMOVE a SET b = a, c = b` stores exactly {b:1, c:2}, and `SET a = c, b = a, c = b` rotates to {a:3, b:1, c:2}.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    key = {'pk': {'S': 'k'}}

    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'k'}, 'a': {'N': '1'}, 'b': {'N': '2'}, 'c': {'N': '3'},
    })
    resp = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='REMOVE a SET b = a, c = b',
        ReturnValues='ALL_NEW',
    )
    returned = resp['Attributes']
    assert returned == {'pk': {'S': 'k'}, 'b': {'N': '1'}, 'c': {'N': '2'}}, (
        f'ALL_NEW was {returned!r}; expected exactly {{pk, b:1, c:2}}'
    )
    stored = _stored(ddb, t, 'k')
    assert stored == {'pk': {'S': 'k'}, 'b': {'N': '1'}, 'c': {'N': '2'}}, (
        f'stored item was {stored!r}; expected exactly {{pk, b:1, c:2}}. '
        f'c == 1 means clauses were evaluated sequentially instead of against one pre-image.'
    )
    assert 'a' not in stored, f'REMOVE a did not take effect: {stored!r}'

    # Clause order in the text does not change the result: SET before REMOVE, rotated.
    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'k'}, 'a': {'N': '1'}, 'b': {'N': '2'}, 'c': {'N': '3'},
    })
    ddb.update_item(TableName=t, Key=key, UpdateExpression='SET a = c, b = a, c = b')
    rotated = _stored(ddb, t, 'k')
    assert rotated == {'pk': {'S': 'k'}, 'a': {'N': '3'}, 'b': {'N': '1'}, 'c': {'N': '2'}}, (
        f'SET a = c, b = a, c = b stored {rotated!r}; expected a rotation {{a:3, b:1, c:2}}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
