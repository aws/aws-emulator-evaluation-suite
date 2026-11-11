"""partiql-delete-returning-all-new-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-delete-returning-all-new-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_EXPECTED_MESSAGE = (
    'Invalid returning clause: RETURNING ALL NEW *. '
    'Only RETURNING ALL OLD * is allowed in DELETE statements.'
)


def _error(fn):
    """The (Code, Message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected the statement to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DELETE ... RETURNING ALL NEW * is refused with a ValidationException and deletes nothing, while
    RETURNING ALL OLD * on the same item removes it and returns the removed item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.delete.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqldelrej-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    key = {'pk': {'S': 'p1'}, 'sk': {'S': 's1'}}
    item = {**key, 'name': {'S': 'Ada'}, 'qty': {'N': '3'}}
    ddb.put_item(TableName=table, Item=item)
    where = "WHERE pk = 'p1' AND sk = 's1'"

    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'DELETE FROM "{table}" {where} RETURNING ALL NEW *'))
    assert code == 'ValidationException', (
        f'DELETE ... RETURNING ALL NEW * must be refused with ValidationException, got {code!r}'
    )
    assert message == _EXPECTED_MESSAGE, (
        f'expected message {_EXPECTED_MESSAGE!r}, got {message!r}'
    )
    kept = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert kept == item, f'the refused DELETE must leave the item intact; it now reads {kept!r}'

    # Positive control: the valid RETURNING form of the same DELETE removes the item.
    removed = ddb.execute_statement(Statement=f'DELETE FROM "{table}" {where} RETURNING ALL OLD *')
    assert removed['Items'] == [item], (
        f'DELETE ... RETURNING ALL OLD * must return the removed item {[item]!r}, got '
        f'{removed["Items"]!r}'
    )
    gone = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert gone is None, f'the valid DELETE must remove the item, a consistent read found {gone!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
