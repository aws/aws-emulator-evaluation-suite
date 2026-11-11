"""transact-write-items-empty-index-key-validates-not-cancels."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-empty-index-key-validates-not-cancels"
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _raises(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return exc
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """An EMPTY-STRING index key is caught by up-front input validation, so it is a top-level
    ValidationException -- the opposite arm from a wrong-type key. An engine that wraps this as
    a TransactionCanceledException diverges, so the two arms pin each other."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    exc = _raises(
        lambda: ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'b'}, 'sk': {'S': '1'}, 'gpk': {'S': ''}}}}]),
        'a transaction whose index key is the empty string',
    )
    err = getattr(exc, 'response', {}).get('Error', {}) or {}
    assert err.get('Code') == 'ValidationException', (
        f"an empty index key is up-front input validation, not a cancellation; got {err.get('Code')}"
    )
    expected = (
        'One or more parameter values are not valid. A value specified for a secondary index key is '
        'not supported. The AttributeValue for a key attribute cannot contain an empty string value. '
        'IndexName: gsi1, IndexKey: gpk'
    )
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, 'nothing may be written'
    exc_update = _raises(
        lambda: ddb.transact_write_items(TransactItems=[
            {'Update': {
                'TableName': table,
                'Key': {'pk': {'S': 'b'}, 'sk': {'S': '1'}},
                'UpdateExpression': 'SET gpk = :v',
                'ExpressionAttributeValues': {':v': {'S': ''}},
            }}]),
        'a transaction whose Update sets an index key to the empty string',
    )
    err_update = getattr(exc_update, 'response', {}).get('Error', {}) or {}
    assert err_update.get('Code') == 'ValidationException', (
        f"an empty index key via Update is up-front input validation too, not a cancellation; "
        f"got {err_update.get('Code')}"
    )
    expected_update = (
        'One or more parameter values are not valid. The update expression attempted to update '
        'a secondary index key to a value that is not supported. The AttributeValue for a key '
        'attribute cannot contain an empty string value.'
    )
    assert err_update.get('Message') == expected_update, (
        f"expected message {expected_update!r}, got {err_update.get('Message')!r}"
    )
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, 'nothing may be written'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
