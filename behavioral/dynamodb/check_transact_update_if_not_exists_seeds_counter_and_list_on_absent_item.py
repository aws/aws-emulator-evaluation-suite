"""transact-update-if-not-exists-seeds-counter-and-list-on-absent-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'transact-update-if-not-exists-seeds-counter-and-list-on-absent-item'
GROUP = 'transactions'
SERVICES = ['dynamodb']


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Update on an absent key creates the item, if_not_exists seeding a counter
    and a list_append target, and a second transaction applies the same expression to stored values.

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

    expression = 'SET c = if_not_exists(c, :zero) + :one, h = list_append(if_not_exists(h, :empty), :tail)'

    def _items(tail: str, marker: str) -> list:
        return [
            {'Put': {'TableName': t, 'Item': {'pk': {'S': marker}}}},
            {'Update': {
                'TableName': t,
                'Key': {'pk': {'S': 'doc'}},
                'UpdateExpression': expression,
                'ExpressionAttributeValues': {
                    ':zero': {'N': '0'}, ':one': {'N': '1'}, ':empty': {'L': []},
                    ':tail': {'L': [{'S': tail}]},
                },
            }},
        ]

    absent = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)
    assert 'Item' not in absent, f'the fresh table already held the item: {absent.get("Item")!r}'

    ddb.transact_write_items(TransactItems=_items('a', 'marker-1'))
    doc = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True).get('Item')
    assert doc == {'pk': {'S': 'doc'}, 'c': {'N': '1'}, 'h': {'L': [{'S': 'a'}]}}, (
        f'the first transaction created {doc!r}'
    )

    ddb.transact_write_items(TransactItems=_items('b', 'marker-2'))
    doc = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True).get('Item')
    assert doc == {'pk': {'S': 'doc'}, 'c': {'N': '2'}, 'h': {'L': [{'S': 'a'}, {'S': 'b'}]}}, (
        f'the second transaction left {doc!r}'
    )
    for marker in ('marker-1', 'marker-2'):
        got = ddb.get_item(TableName=t, Key={'pk': {'S': marker}}, ConsistentRead=True).get('Item')
        assert got == {'pk': {'S': marker}}, f'the Put committed beside the Update read {got!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
