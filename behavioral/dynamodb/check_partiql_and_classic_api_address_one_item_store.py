"""partiql-and-classic-api-address-one-item-store."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-and-classic-api-address-one-item-store"
GROUP = 'partiql'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PartiQL and the classic API share one item store: inserts, updates and deletes made through
    either are visible through the other, compared as whole items."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlstore-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def _select(pk):
        return ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}" WHERE pk = ?',
            Parameters=[{'S': pk}],
            ConsistentRead=True,
        )['Items']

    def _get(pk):
        return ddb.get_item(
            TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True,
        ).get('Item')

    # --- a PartiQL INSERT is visible to GetItem ---
    ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'pk\': ?, \'body\': ?, \'n\': ?}}',
        Parameters=[{'S': 'via-partiql'}, {'S': 'inserted'}, {'N': '1'}],
    )
    inserted = {'pk': {'S': 'via-partiql'}, 'body': {'S': 'inserted'}, 'n': {'N': '1'}}
    assert _get('via-partiql') == inserted, (
        f'an item inserted with PartiQL must be readable by a strongly consistent GetItem: '
        f'expected {inserted!r}, got {_get("via-partiql")!r}'
    )

    # --- a classic PutItem is visible to a PartiQL SELECT ---
    written = {'pk': {'S': 'via-classic'}, 'body': {'S': 'written'}, 'n': {'N': '2'}}
    ddb.put_item(TableName=table, Item=written)
    assert _select('via-classic') == [written], (
        f'an item written with PutItem must be returned by a PartiQL SELECT: expected '
        f'{[written]!r}, got {_select("via-classic")!r}'
    )

    # --- a PartiQL UPDATE is visible to GetItem ---
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET body = ? WHERE pk = ?',
        Parameters=[{'S': 'partiql-updated'}, {'S': 'via-classic'}],
    )
    expected = dict(written, body={'S': 'partiql-updated'})
    assert _get('via-classic') == expected, (
        f'a PartiQL UPDATE must be visible to GetItem: expected {expected!r}, got '
        f'{_get("via-classic")!r}'
    )

    # --- a classic UpdateItem is visible to a PartiQL SELECT ---
    ddb.update_item(
        TableName=table,
        Key={'pk': {'S': 'via-partiql'}},
        UpdateExpression='SET body = :b',
        ExpressionAttributeValues={':b': {'S': 'classic-updated'}},
    )
    expected = dict(inserted, body={'S': 'classic-updated'})
    assert _select('via-partiql') == [expected], (
        f'an UpdateItem must be visible to a PartiQL SELECT: expected {[expected]!r}, got '
        f'{_select("via-partiql")!r}'
    )

    # --- a PartiQL DELETE removes the item for GetItem too ---
    ddb.execute_statement(
        Statement=f'DELETE FROM "{table}" WHERE pk = ?',
        Parameters=[{'S': 'via-classic'}],
    )
    assert _get('via-classic') is None, (
        f'a PartiQL DELETE must remove the item for GetItem as well, found '
        f'{_get("via-classic")!r}'
    )

    # --- a classic DeleteItem removes the item for PartiQL too ---
    ddb.delete_item(TableName=table, Key={'pk': {'S': 'via-partiql'}})
    assert _select('via-partiql') == [], (
        f'a DeleteItem must remove the item for a PartiQL SELECT as well, found '
        f'{_select("via-partiql")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
