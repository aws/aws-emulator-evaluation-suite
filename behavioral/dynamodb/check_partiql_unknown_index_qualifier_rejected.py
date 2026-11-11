"""partiql-unknown-index-qualifier-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-unknown-index-qualifier-rejected"
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
    """PartiQL SELECT naming an index the table does not have is refused with ValidationException,
    not answered as an empty result set. A FROM path of more than two components, and one with an
    empty component, are refused the same way before the index name is even looked up."""
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
    err = _error_code(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."nope" WHERE pk = \'a\''),
        'a PartiQL statement naming a nonexistent index',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'The table does not have the specified index'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    err = _error_code(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."gsi1"."extra" WHERE gpk = \'g\''),
        'a PartiQL FROM path of three components',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'A path may contain at most 2 components in the FROM clause'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    err = _error_code(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."" WHERE pk = \'a\''),
        'a PartiQL FROM path with an empty index component',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'Path component cannot be an empty string'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
