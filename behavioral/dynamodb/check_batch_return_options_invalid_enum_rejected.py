"""batch-return-options-invalid-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-return-options-invalid-enum-rejected"
GROUP = 'batch'
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
    """An out-of-enum ReturnConsumedCapacity (BatchGetItem, BatchWriteItem) or
    ReturnItemCollectionMetrics (BatchWriteItem) is ValidationException naming the member
    and echoing the value; the table gains nothing from any rejected call.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    # Positive control: a well-formed batch write/read round trip works in this account,
    # so a rejection below is attributable to the enum value and not to a broken client.
    ddb.batch_write_item(RequestItems={t: [{'PutRequest': {'Item': {'pk': {'S': 'control'}}}}]})
    got = ddb.batch_get_item(RequestItems={t: {'Keys': [{'pk': {'S': 'control'}}], 'ConsistentRead': True}})
    assert got['Responses'][t] == [{'pk': {'S': 'control'}}], f'positive control not visible: {got}'

    code, message = _error(lambda: ddb.batch_get_item(
        RequestItems={t: {'Keys': [{'pk': {'S': 'rcc-get'}}]}},
        ReturnConsumedCapacity='BOGUS',
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to "
        "satisfy constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]"
    ), f'unexpected message {message!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'rcc-get'}}, ConsistentRead=True)
    assert 'Item' not in after, f'a rejected BatchGetItem must write nothing, found {after}'

    code, message = _error(lambda: ddb.batch_write_item(
        RequestItems={t: [{'PutRequest': {'Item': {'pk': {'S': 'rcc-write'}}}}]},
        ReturnConsumedCapacity='BOGUS',
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to "
        "satisfy constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]"
    ), f'unexpected message {message!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'rcc-write'}}, ConsistentRead=True)
    assert 'Item' not in after, f'a rejected BatchWriteItem must write nothing, found {after}'

    code, message = _error(lambda: ddb.batch_write_item(
        RequestItems={t: [{'PutRequest': {'Item': {'pk': {'S': 'ricm-write'}}}}]},
        ReturnItemCollectionMetrics='BOGUS',
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "1 validation error detected: Value 'BOGUS' at 'returnItemCollectionMetrics' failed to "
        "satisfy constraint: Member must satisfy enum value set: [SIZE, NONE]"
    ), f'unexpected message {message!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'ricm-write'}}, ConsistentRead=True)
    assert 'Item' not in after, f'a rejected BatchWriteItem must write nothing, found {after}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
