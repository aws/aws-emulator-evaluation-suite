"""update-item-and-transact-update-empty-gsi-and-lsi-keys-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-and-transact-update-empty-gsi-and-lsi-keys-rejected"
GROUP = 'access_path'
SERVICES = ['dynamodb']


def _error(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return exc
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


_GSI_MESSAGE = ('One or more parameter values are not valid. The update expression attempted to '
                'update a secondary index key to a value that is not supported. The AttributeValue '
                'for a key attribute cannot contain an empty string value.')
_LSI_MESSAGE = ('One or more parameter values are not valid. The update expression attempted to '
                'update a secondary index key to a value that is not supported. The AttributeValue '
                'for a key attribute cannot contain an empty binary value.')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """UpdateItem and TransactWriteItems Update setting a GSI key to an empty S or an LSI key to
    an empty B are refused with ValidationException, up front and never as a cancellation."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'B'},
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})
    key = {'pk': {'S': 'b'}, 'sk': {'S': '1'}}
    ddb.put_item(TableName=table, Item=key)

    exc = _error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression='SET gpk = :v',
            ExpressionAttributeValues={':v': {'S': ''}},
        ),
        'UpdateItem setting the GSI key to an empty S',
    )
    err = getattr(exc, 'response', {}).get('Error', {}) or {}
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    assert err.get('Message') == _GSI_MESSAGE, f"expected message {_GSI_MESSAGE!r}, got {err.get('Message')!r}"

    exc = _error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression='SET lsk = :v',
            ExpressionAttributeValues={':v': {'B': b''}},
        ),
        'UpdateItem setting the LSI key to an empty B',
    )
    err = getattr(exc, 'response', {}).get('Error', {}) or {}
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    assert err.get('Message') == _LSI_MESSAGE, f"expected message {_LSI_MESSAGE!r}, got {err.get('Message')!r}"

    exc = _error(
        lambda: ddb.transact_write_items(TransactItems=[{'Update': {
            'TableName': table, 'Key': key, 'UpdateExpression': 'SET gpk = :v',
            'ExpressionAttributeValues': {':v': {'S': ''}},
        }}]),
        'TransactWriteItems Update setting the GSI key to an empty S',
    )
    err = getattr(exc, 'response', {}).get('Error', {}) or {}
    assert err.get('Code') == 'ValidationException', (
        f"an empty index key fails up-front validation rather than cancelling the transaction; "
        f"got {err.get('Code')}"
    )
    assert err.get('Message') == _GSI_MESSAGE, f"expected message {_GSI_MESSAGE!r}, got {err.get('Message')!r}"
    assert exc.response.get('CancellationReasons') is None, (
        f"an up-front validation failure carries no CancellationReasons; got "
        f"{exc.response.get('CancellationReasons')!r}"
    )

    exc = _error(
        lambda: ddb.transact_write_items(TransactItems=[{'Update': {
            'TableName': table, 'Key': key, 'UpdateExpression': 'SET lsk = :v',
            'ExpressionAttributeValues': {':v': {'B': b''}},
        }}]),
        'TransactWriteItems Update setting the LSI key to an empty B',
    )
    err = getattr(exc, 'response', {}).get('Error', {}) or {}
    assert err.get('Code') == 'ValidationException', (
        f"an empty index key fails up-front validation rather than cancelling the transaction; "
        f"got {err.get('Code')}"
    )
    assert err.get('Message') == _LSI_MESSAGE, f"expected message {_LSI_MESSAGE!r}, got {err.get('Message')!r}"
    assert exc.response.get('CancellationReasons') is None, (
        f"an up-front validation failure carries no CancellationReasons; got "
        f"{exc.response.get('CancellationReasons')!r}"
    )

    held = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert held == key, f"the four refused updates must leave the item unchanged, got {held!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
