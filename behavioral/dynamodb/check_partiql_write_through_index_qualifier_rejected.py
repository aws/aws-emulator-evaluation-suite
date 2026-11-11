"""partiql-write-through-index-qualifier-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-write-through-index-qualifier-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """PartiQL cannot write through an index. UPDATE, INSERT and DELETE addressed at
    "table"."index" are each refused, so a target that silently wrote to the base table would
    diverge invisibly."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g1'}, 'lsk': {'N': '5'}})
    err = _error_code(
        lambda: ddb.execute_statement(Statement=f'UPDATE "{table}"."gsi1" SET extra=\'z\' WHERE gpk=\'g1\''),
        'a PartiQL UPDATE addressed at an index',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'This operation is not supported on an index'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}, 'sk': {'S': '1'}}, ConsistentRead=True)['Item']
    assert 'extra' not in got, 'the refused UPDATE must leave the base item unchanged'

    err = _error_code(
        lambda: ddb.execute_statement(
            Statement=f"INSERT INTO \"{table}\".\"gsi1\" VALUE {{'pk':'z','sk':'9','gpk':'g9'}}"
        ),
        'a PartiQL INSERT addressed at an index',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = (
        'FROM clause may only contain a single table name in data manipulation statements'
        f' at 1:13:{len(table) + 2}'
    )
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    inserted = ddb.get_item(TableName=table, Key={'pk': {'S': 'z'}, 'sk': {'S': '9'}}, ConsistentRead=True)
    assert 'Item' not in inserted, 'the refused INSERT must not create the item'

    err = _error_code(
        lambda: ddb.execute_statement(Statement=f'DELETE FROM "{table}"."gsi1" WHERE gpk=\'g1\''),
        'a PartiQL DELETE addressed at an index',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'This operation is not supported on an index'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    still_there = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}, 'sk': {'S': '1'}}, ConsistentRead=True)
    assert 'Item' in still_there, 'the refused DELETE must leave the base item in place'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
