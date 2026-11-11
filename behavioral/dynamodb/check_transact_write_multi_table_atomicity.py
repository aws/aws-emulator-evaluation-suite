"""transact-write-multi-table-atomicity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-multi-table-atomicity"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected {ERR_TRANSACTION_CANCELED}, but the call SUCCEEDED and returned {result!r}')


def _simple_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(TableName=name, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': 'transact-write-multi-table-atomicity'}])
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems call spanning TWO distinct tables commits both tables' writes together
    when every condition holds, and rolls back BOTH tables' writes together (including the op with
    no condition of its own) when a condition on either table fails.
    """
    ddb = ctx.client('dynamodb')
    table_a = _simple_table(ctx, ddb, 'sim2real-behav-twma-a-')
    table_b = _simple_table(ctx, ddb, 'sim2real-behav-twma-b-')
    key_a = {'pk': {'S': 'row-a'}}
    key_b = {'pk': {'S': 'row-b'}}
    ddb.put_item(TableName=table_a, Item={**key_a, 'status': {'S': 'ok'}})
    ddb.put_item(TableName=table_b, Item={**key_b, 'v': {'N': '1'}})

    # --- success: both tables mutate together.
    ddb.transact_write_items(
        TransactItems=[
            {
                'ConditionCheck': {
                    'TableName': table_a,
                    'Key': key_a,
                    'ConditionExpression': '#s = :ok',
                    'ExpressionAttributeNames': {'#s': 'status'},
                    'ExpressionAttributeValues': {':ok': {'S': 'ok'}},
                }
            },
            {
                'Update': {
                    'TableName': table_b,
                    'Key': key_b,
                    'UpdateExpression': 'SET v = :two',
                    'ExpressionAttributeValues': {':two': {'N': '2'}},
                }
            },
        ]
    )
    b_after_success = ddb.get_item(TableName=table_b, Key=key_b, ConsistentRead=True)['Item']
    assert b_after_success['v'] == {'N': '2'}, b_after_success

    # --- failure: table_b's condition fails -> table_a's unconditioned Put must ALSO roll back.
    code, message = _error(
        lambda: ddb.transact_write_items(
            TransactItems=[
                {
                    'Put': {
                        'TableName': table_a,
                        'Item': {'pk': {'S': 'row-a-new'}, 'created': {'BOOL': True}},
                    }
                },
                {
                    'Update': {
                        'TableName': table_b,
                        'Key': key_b,
                        'UpdateExpression': 'SET v = :three',
                        'ConditionExpression': 'v = :wrong',
                        'ExpressionAttributeValues': {':three': {'N': '3'}, ':wrong': {'N': '999'}},
                    }
                },
            ]
        )
    )
    assert code == ERR_TRANSACTION_CANCELED, f'expected {ERR_TRANSACTION_CANCELED}, got {code}'
    expected_message = (
        'Transaction cancelled, please refer cancellation reasons for specific reasons '
        '[None, ConditionalCheckFailed]'
    )
    assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'

    never_written = ddb.get_item(
        TableName=table_a, Key={'pk': {'S': 'row-a-new'}}, ConsistentRead=True
    )
    assert 'Item' not in never_written, 'cross-table sibling op must not partially apply on rollback'
    b_unchanged = ddb.get_item(TableName=table_b, Key=key_b, ConsistentRead=True)['Item']
    assert b_unchanged['v'] == {'N': '2'}, 'the failing table item must remain at its pre-txn value'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
