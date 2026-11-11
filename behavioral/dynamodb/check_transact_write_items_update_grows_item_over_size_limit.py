"""transact-write-items-update-grows-item-over-size-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-update-grows-item-over-size-limit"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
LIMIT_BYTES = 409600


def _error_code_and_message(fn) -> tuple[str, str]:
    """The Error Code and Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Update that would grow a stored item past the size limit is
    refused as a top-level ValidationException, never a TransactionCanceledException,
    and the stored item is left unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    # Positive control: TransactWriteItems Update of a small, in-bounds grow succeeds and
    # reads back, so a target that rejects every transactional update fails here too.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'small'}, 'data': {'S': 'start'}})
    ddb.transact_write_items(TransactItems=[{'Update': {
        'TableName': table,
        'Key': {'pk': {'S': 'small'}},
        'UpdateExpression': 'SET #d = :v',
        'ExpressionAttributeNames': {'#d': 'data'},
        'ExpressionAttributeValues': {':v': {'S': 'grown-but-still-small'}},
    }}])
    control_got = ddb.get_item(TableName=table, Key={'pk': {'S': 'small'}}, ConsistentRead=True)
    assert control_got.get('Item', {}).get('data', {}).get('S') == 'grown-but-still-small', (
        f'positive control TransactWriteItems Update failed, got {control_got.get("Item")}'
    )

    # The focus: a stored item grown, through TransactWriteItems Update, past the limit.
    original = 'o' * 1024
    ddb.put_item(TableName=table, Item={'pk': {'S': 'grow'}, 'data': {'S': original}})

    grown_value = 'g' * (LIMIT_BYTES + 1 - len('pk'.encode()) - len('grow'.encode()) - len('data'.encode()))
    code, message = _error_code_and_message(lambda: ddb.transact_write_items(TransactItems=[{'Update': {
        'TableName': table,
        'Key': {'pk': {'S': 'grow'}},
        'UpdateExpression': 'SET #d = :v',
        'ExpressionAttributeNames': {'#d': 'data'},
        'ExpressionAttributeValues': {':v': {'S': grown_value}},
    }}]))
    assert code == ERR_VALIDATION, (
        f'a TransactWriteItems Update growing an item past {LIMIT_BYTES} bytes must be {ERR_VALIDATION}, '
        f'not TransactionCanceledException, got {code!r}: {message!r}'
    )
    assert message == 'Item size to update has exceeded the maximum allowed size', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key={'pk': {'S': 'grow'}}, ConsistentRead=True)
    assert unchanged.get('Item', {}).get('data', {}).get('S') == original, (
        f'a TransactWriteItems Update rejected for size must leave the item unchanged, got {unchanged.get("Item")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
