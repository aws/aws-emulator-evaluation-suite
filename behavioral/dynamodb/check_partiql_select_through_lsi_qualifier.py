"""partiql-select-through-lsi-qualifier."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-select-through-lsi-qualifier"
GROUP = 'partiql'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """PartiQL SELECT through an LSI qualifier honours the index projection: a KEYS_ONLY LSI
    returns only the table and index keys, and a WHERE on an attribute the index does not
    project is refused rather than silently filtered."""
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
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g1'}, 'lsk': {'N': '5'}, 'extra': {'S': 'e'}})
    res = ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."lsi1" WHERE pk = \'a\'')
    items = res.get('Items', [])
    assert len(items) == 1, f'expected one item through the LSI, got {len(items)}'
    got = set(items[0])
    assert got == {'pk', 'sk', 'lsk'}, f'KEYS_ONLY must project only the keys, got {sorted(got)}'

    err = _error_code(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."lsi1" WHERE pk = \'a\' AND extra = \'e\''),
        'a PartiQL WHERE filtering on an attribute the KEYS_ONLY LSI does not project',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'One or more parameter values were invalid: Secondary index lsi1 does not project one or more filter attributes: [extra]'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
