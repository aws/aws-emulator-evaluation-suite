"""transact-condition-check-unknown-attribute-type-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'transact-condition-check-unknown-attribute-type-name-rejected'
GROUP = 'transactions'
SERVICES = ['dynamodb']
CANCELED = 'TransactionCanceledException'
CANCELED_PREFIX = 'Transaction cancelled, please refer cancellation reasons for specific reasons '
VALIDATION = 'ValidationException'
UNKNOWN_TYPE = ('Invalid ConditionExpression: Invalid attribute type name found; type: {}, '
                'valid types: {{S,SS,N,NS,B,BS,BOOL,NULL,L,M}}')


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
    """attribute_type naming a type outside the case-sensitive set refuses the whole TransactWriteItems
    call, while a valid name that does not match cancels it as a condition failure.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
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

    stored = {'pk': {'S': 'doc'}, 's': {'S': 'text'}}
    ddb.put_item(TableName=t, Item=stored)

    def _items(type_name: str) -> list:
        return [
            {'Put': {'TableName': t, 'Item': {'pk': {'S': 'sibling'}, 'v': {'N': '1'}}}},
            {'ConditionCheck': {
                'TableName': t,
                'Key': {'pk': {'S': 'doc'}},
                'ConditionExpression': 'attribute_type(s, :t)',
                'ExpressionAttributeValues': {':t': {'S': type_name}},
            }},
        ]

    for name in ('X', 's'):
        err = _refusal(lambda: ddb.transact_write_items(TransactItems=_items(name)))
        assert err['Error']['Code'] == VALIDATION, f'type {name!r}: expected {VALIDATION}, got {err["Error"]!r}'
        assert err['Error'].get('Message') == UNKNOWN_TYPE.format(name), (
            f'type {name!r}: expected {UNKNOWN_TYPE.format(name)!r}, got {err["Error"].get("Message")!r}'
        )
        assert 'CancellationReasons' not in err, (
            f'type {name!r}: a request-level refusal carried cancellation reasons {err["CancellationReasons"]!r}'
        )

    # Legal neighbour: a valid type name that does not match the stored type is a condition failure.
    err = _refusal(lambda: ddb.transact_write_items(TransactItems=_items('N')))
    assert err['Error']['Code'] == CANCELED, f'type N: expected {CANCELED}, got {err["Error"]!r}'
    assert err['Error'].get('Message') == CANCELED_PREFIX + '[None, ConditionalCheckFailed]', (
        f'type N: message was {err["Error"].get("Message")!r}'
    )
    assert err.get('CancellationReasons') == [
        {'Code': 'None'},
        {'Code': 'ConditionalCheckFailed', 'Message': 'The conditional request failed'},
    ], f'type N: cancellation reasons were {err.get("CancellationReasons")!r}'

    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True)
    assert 'Item' not in sibling, f'a refused transaction wrote its sibling Put: {sibling.get("Item")!r}'

    # Positive control: the matching type name lets the transaction commit.
    ddb.transact_write_items(TransactItems=_items('S'))
    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True).get('Item')
    assert sibling == {'pk': {'S': 'sibling'}, 'v': {'N': '1'}}, f'the committed sibling read {sibling!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert after == stored, f'a ConditionCheck changed the item it checked: {after!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
