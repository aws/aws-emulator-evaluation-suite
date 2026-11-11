"""put-item-gsi-key-type-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-gsi-key-type-mismatch-rejected"
GROUP = 'access_path'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """PutItem carrying an index key whose type contradicts the index AttributeDefinition is
    refused, and the message names the index. Accepting it corrupts the index silently."""
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
        lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'b'}, 'sk': {'S': '1'}, 'gpk': {'N': '9'}}),
        'a PutItem whose GSI key has the wrong type',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = ('One or more parameter values were invalid: Type mismatch for Index Key gpk '
                'Expected: S Actual: N IndexName: gsi1')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, (
        'the refused write must leave the table empty'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
