"""transact-write-items-cancelled-by-condition-failure-reports-no-consumed-capacity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-cancelled-by-condition-failure-reports-no-consumed-capacity"
GROUP = 'capacity'
SERVICES = ['dynamodb']
_CANCELED = ('TransactionCanceledException',
             'Transaction cancelled, please refer cancellation reasons for specific reasons '
             '[ConditionalCheckFailed]')


def expect_error(fn, code, message):
    """Calls ``fn``, asserts it raises ``(code, message)`` and returns the response for
    inspection; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response['Error']['Code']
        got_message = exc.response['Error'].get('Message')
        assert got_code == code, f'expected error code {code!r}, got {got_code!r}'
        assert got_message == message, f'expected message {message!r}, got {got_message!r}'
        return exc.response
    raise AssertionError(f'expected {code} ({message!r}), but the call succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems cancelled by a failing condition reports no ConsumedCapacity in its
    error response and leaves the item unchanged; the same call against a free key commits and
    reports 2 write capacity units for its small item."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    existing = {'pk': {'S': 'present'}, 'payload': {'S': 'original'}}
    ddb.put_item(TableName=table, Item=existing)

    response = expect_error(
        lambda: ddb.transact_write_items(
            ReturnConsumedCapacity='INDEXES',
            TransactItems=[{'Put': {
                'TableName': table,
                'Item': {'pk': {'S': 'present'}, 'payload': {'S': 'clobbered'}},
                'ConditionExpression': 'attribute_not_exists(pk)',
            }}],
        ),
        *_CANCELED,
    )
    assert 'ConsumedCapacity' not in response, (
        f'a cancelled TransactWriteItems error response carried ConsumedCapacity '
        f'{response.get("ConsumedCapacity")!r}, expected none'
    )
    unchanged = ddb.get_item(TableName=table, Key={'pk': {'S': 'present'}}, ConsistentRead=True)['Item']
    assert unchanged == existing, (
        f'the item is {unchanged!r} after a cancelled transaction, expected it unchanged at {existing!r}'
    )

    # --- positive control: the same shape of call against a free key commits and reports its units ---
    committed = ddb.transact_write_items(
        ReturnConsumedCapacity='INDEXES',
        TransactItems=[{'Put': {
            'TableName': table,
            'Item': {'pk': {'S': 'free'}, 'payload': {'S': 'new'}},
            'ConditionExpression': 'attribute_not_exists(pk)',
        }}],
    )['ConsumedCapacity'][0]
    assert committed.get('WriteCapacityUnits') == 2.0, (
        f'a committed TransactWriteItems of a small item reported WriteCapacityUnits '
        f'{committed.get("WriteCapacityUnits")!r}, expected 2.0'
    )
    assert committed.get('CapacityUnits') == 2.0, (
        f'a committed TransactWriteItems of a small item reported CapacityUnits '
        f'{committed.get("CapacityUnits")!r}, expected 2.0'
    )
    assert ddb.get_item(
        TableName=table, Key={'pk': {'S': 'free'}}, ConsistentRead=True
    )['Item'] == {'pk': {'S': 'free'}, 'payload': {'S': 'new'}}, (
        'the positive control item was not committed as written'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
