"""put-batch-write-update-index-key-empty-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-batch-write-update-index-key-empty-value-rejected"
GROUP = 'item-validation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem and BatchWriteItem reject a GSI/LSI key set to an empty string or binary value
    with ValidationException naming IndexName and IndexKey; UpdateItem rejects the identical
    write with the same code but a different message that names neither.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lrk', 'AttributeType': 'B'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lrk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    def gsi_message(attr: str, kind: str) -> str:
        return (
            'One or more parameter values are not valid. A value specified for a secondary '
            f'index key is not supported. The AttributeValue for a key attribute cannot contain '
            f'an empty {kind} value. IndexName: gsi1, IndexKey: {attr}'
        )

    def lsi_message(attr: str, kind: str) -> str:
        return (
            'One or more parameter values are not valid. A value specified for a secondary '
            f'index key is not supported. The AttributeValue for a key attribute cannot contain '
            f'an empty {kind} value. IndexName: lsi1, IndexKey: {attr}'
        )

    def update_message(kind: str) -> str:
        return (
            'One or more parameter values are not valid. The update expression attempted to '
            'update a secondary index key to a value that is not supported. The AttributeValue '
            f'for a key attribute cannot contain an empty {kind} value.'
        )

    # Positive control: a healthy item with both index keys populated is accepted and readable.
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'control'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g'}, 'lrk': {'B': b'l'},
    })
    control = ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}, 'sk': {'S': '1'}},
                            ConsistentRead=True)
    assert 'Item' in control, f'positive control PutItem did not persist: {control!r}'

    # PutItem: empty-string GSI key, and empty-binary LSI key.
    code, message = _error(lambda: ddb.put_item(TableName=table, Item={
        'pk': {'S': 'put-gsi'}, 'sk': {'S': '1'}, 'gpk': {'S': ''}}))
    assert code == ERR_VALIDATION, f'PutItem/GSI: expected {ERR_VALIDATION}, got {code}: {message!r}'
    put_gsi_message = gsi_message('gpk', 'string')
    assert message == put_gsi_message, f'PutItem/GSI: expected {put_gsi_message!r}, got {message!r}'

    code, message = _error(lambda: ddb.put_item(TableName=table, Item={
        'pk': {'S': 'put-lsi'}, 'sk': {'S': '1'}, 'lrk': {'B': b''}}))
    assert code == ERR_VALIDATION, f'PutItem/LSI: expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == lsi_message('lrk', 'binary'), f'PutItem/LSI: got {message!r}'

    # BatchWriteItem: same two emptiness violations, each its own request item.
    code, message = _error(lambda: ddb.batch_write_item(RequestItems={table: [
        {'PutRequest': {'Item': {'pk': {'S': 'batch-gsi'}, 'sk': {'S': '1'}, 'gpk': {'S': ''}}}}]}))
    assert code == ERR_VALIDATION, f'BatchWriteItem/GSI: expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == put_gsi_message, (
        f'BatchWriteItem/GSI: expected the same message as PutItem/GSI {put_gsi_message!r}, got {message!r}'
    )

    code, message = _error(lambda: ddb.batch_write_item(RequestItems={table: [
        {'PutRequest': {'Item': {'pk': {'S': 'batch-lsi'}, 'sk': {'S': '1'}, 'lrk': {'B': b''}}}}]}))
    assert code == ERR_VALIDATION, f'BatchWriteItem/LSI: expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == lsi_message('lrk', 'binary'), f'BatchWriteItem/LSI: got {message!r}'

    # UpdateItem: the identical violation on an item that already exists, through SET.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd'}, 'sk': {'S': '1'}})
    code, update_gsi = _error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'upd'}, 'sk': {'S': '1'}},
        UpdateExpression='SET gpk = :g', ExpressionAttributeValues={':g': {'S': ''}}))
    assert code == ERR_VALIDATION, f'UpdateItem/GSI: expected {ERR_VALIDATION}, got {code}: {update_gsi!r}'
    assert update_gsi == update_message('string'), f'UpdateItem/GSI: got {update_gsi!r}'

    code, update_lsi = _error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'upd'}, 'sk': {'S': '1'}},
        UpdateExpression='SET lrk = :l', ExpressionAttributeValues={':l': {'B': b''}}))
    assert code == ERR_VALIDATION, f'UpdateItem/LSI: expected {ERR_VALIDATION}, got {code}: {update_lsi!r}'
    assert update_lsi == update_message('binary'), f'UpdateItem/LSI: got {update_lsi!r}'

    # The comparison the scope asks for: UpdateItem's message names neither the index nor the
    # key, unlike PutItem's and BatchWriteItem's, though both report the same error code.
    assert put_gsi_message != update_gsi, 'PutItem and UpdateItem must not share one message'
    assert 'IndexName' not in update_gsi and 'IndexKey' not in update_gsi, (
        f'UpdateItem message unexpectedly names an index or key: {update_gsi!r}'
    )
    assert 'IndexName' in put_gsi_message and 'IndexKey' in put_gsi_message, (
        'PutItem message must name the index and the key'
    )

    # Nothing any of the four rejected writes could leave behind, and the update left the
    # existing item's index keys unset rather than corrupted to the empty value.
    held = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd'}, 'sk': {'S': '1'}}, ConsistentRead=True)['Item']
    assert 'gpk' not in held and 'lrk' not in held, f'the rejected updates mutated the item: {held!r}'
    for pk in ('put-gsi', 'put-lsi', 'batch-gsi', 'batch-lsi'):
        missing = ddb.get_item(TableName=table, Key={'pk': {'S': pk}, 'sk': {'S': '1'}}, ConsistentRead=True)
        assert 'Item' not in missing, f'the rejected write for {pk!r} was persisted: {missing!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
