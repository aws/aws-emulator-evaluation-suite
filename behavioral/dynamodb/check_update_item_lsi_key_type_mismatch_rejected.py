"""update-item-lsi-key-type-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-lsi-key-type-mismatch-rejected"
GROUP = 'lsi'
SERVICES = ['dynamodb']


def _error(call, what):
    try:
        result = call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it, returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """UpdateItem SET on an LSI sort key whose value type contradicts the index
    AttributeDefinition is refused, and a same-shape update with the declared type succeeds."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-lsitype-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'lsisk', 'AttributeType': 'S'}],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                         {'AttributeName': 'lsisk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {'pk': {'S': 'ITEM#1'}, 'sk': {'S': 'S1'}}
    ddb.put_item(TableName=table, Item={**key, 'lsisk': {'S': 'A'}, 'payload': {'S': 'p'}})

    err = _error(
        lambda: ddb.update_item(TableName=table, Key=key,
                                UpdateExpression='SET lsisk = :v',
                                ExpressionAttributeValues={':v': {'N': '5'}}),
        'an UpdateItem whose LSI key has the wrong type',
    )
    assert err.get('Code') == 'ValidationException', (
        f"expected ValidationException, got {err.get('Code')!r}: {err.get('Message')!r}"
    )
    expected = ('One or more parameter values were invalid: Type mismatch for Index Key lsisk '
                'Expected: S Actual: N IndexName: lsi1')
    assert err.get('Message') == expected, f'expected message {expected!r}, got {err.get("Message")!r}'

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert unchanged['lsisk'] == {'S': 'A'}, (
        f'the refused update must leave the LSI key untouched: {unchanged!r}'
    )

    ddb.update_item(TableName=table, Key=key,
                    UpdateExpression='SET lsisk = :v',
                    ExpressionAttributeValues={':v': {'S': 'B'}})
    updated = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert updated['lsisk'] == {'S': 'B'}, (
        f'a correctly typed UpdateItem on the LSI key must still succeed: {updated!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
