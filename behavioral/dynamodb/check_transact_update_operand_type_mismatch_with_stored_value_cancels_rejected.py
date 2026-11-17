"""transact-update-operand-type-mismatch-with-stored-value-cancels-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'transact-update-operand-type-mismatch-with-stored-value-cancels-rejected'
GROUP = 'transactions'
SERVICES = ['dynamodb']
CANCELED = 'TransactionCanceledException'
CANCELED_PREFIX = 'Transaction cancelled, please refer cancellation reasons for specific reasons '
WRONG_TYPE = 'An operand in the update expression has an incorrect data type'


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise

    return run_undo


def _refusal(fn) -> dict:
    """The error response ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Update member whose ADD, arithmetic or list_append meets a stored value of the wrong type
    cancels the transaction with a ValidationError reason, and no member is applied.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
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
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 150})

    stored = {'pk': {'S': 'doc'}, 's': {'S': 'text'}, 'n': {'N': '5'}, 'h': {'L': [{'S': 'a'}]}}
    ddb.put_item(TableName=t, Item=stored)

    def _items(update_expression: str, values: dict) -> list:
        return [
            {'Put': {'TableName': t, 'Item': {'pk': {'S': 'sibling'}, 'v': {'N': '1'}}}},
            {'Update': {
                'TableName': t,
                'Key': {'pk': {'S': 'doc'}},
                'UpdateExpression': update_expression,
                'ExpressionAttributeValues': values,
            }},
        ]

    one = {':one': {'N': '1'}}
    tail = {':tail': {'L': [{'S': 'b'}]}}
    # Each operand is well-typed on its own; only the stored value it meets is of the wrong type.
    for expression, values in (
        ('ADD s :one', one),
        ('SET s = s - :one', one),
        ('SET n = list_append(n, :tail)', tail),
    ):
        err = _refusal(lambda: ddb.transact_write_items(TransactItems=_items(expression, values)))
        assert err['Error']['Code'] == CANCELED, f'{expression}: expected {CANCELED}, got {err["Error"]!r}'
        expected = CANCELED_PREFIX + '[None, ValidationError]'
        assert err['Error'].get('Message') == expected, (
            f'{expression}: expected message {expected!r}, got {err["Error"].get("Message")!r}'
        )
        reasons = err.get('CancellationReasons')
        assert reasons == [
            {'Code': 'None'},
            {'Code': 'ValidationError', 'Message': WRONG_TYPE},
        ], f'{expression}: cancellation reasons were {reasons!r}'

    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True)
    assert 'Item' not in sibling, f'a cancelled transaction wrote its sibling Put: {sibling.get("Item")!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert after == stored, f'a cancelled transaction changed the stored item: {after!r}'

    # Positive control: the same operators on attributes of the matching stored type commit.
    ddb.transact_write_items(TransactItems=_items(
        'ADD n :one SET h = list_append(h, :tail)', {**one, **tail},
    ))
    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True).get('Item')
    assert sibling == {'pk': {'S': 'sibling'}, 'v': {'N': '1'}}, f'the committed sibling read {sibling!r}'
    doc = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert doc == {
        'pk': {'S': 'doc'}, 's': {'S': 'text'}, 'n': {'N': '6'}, 'h': {'L': [{'S': 'a'}, {'S': 'b'}]},
    }, f'the committed update read back as {doc!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
