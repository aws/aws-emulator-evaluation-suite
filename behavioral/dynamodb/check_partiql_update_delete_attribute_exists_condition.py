"""partiql-update-delete-attribute-exists-condition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-delete-attribute-exists-condition"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_CCF = 'ConditionalCheckFailedException'
MSG_CCF = 'The conditional request failed'


def _wait_table_active(ctx, ddb, table_name):
    """Poll DescribeTable until TableStatus is ACTIVE, bounded by the run's remaining time."""
    left = ctx.time_left()
    budget_s = 90.0 if left is None else max(5.0, min(90.0, left - 10.0))
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)['Table']
        if last['TableStatus'] == 'ACTIVE':
            return last
        time.sleep(1.0)
    raise AssertionError(f'table {table_name} never went ACTIVE in {budget_s}s: {last!r}')


def _error(fn):
    """Call fn(); return (code, message), raising on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE/DELETE WHERE clause testing attribute_exists/attribute_not_exists on a
    non-key attribute acts as a write condition: the write applies when the predicate holds and
    fails with ConditionalCheckFailedException, item unchanged, when it does not.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.delete.html
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
    _wait_table_active(ctx, ddb, t)

    key = {'pk': {'S': 'p1'}}
    ddb.put_item(TableName=t, Item={**key, 'flag': {'S': 'active'}, 'amount': {'N': '1'}})

    # attribute_exists(flag) holds (flag is present): the UPDATE applies.
    ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET amount = ? WHERE pk = ? AND attribute_exists(flag)',
        Parameters=[{'N': '2'}, {'S': 'p1'}],
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert item['amount'] == {'N': '2'}, (
        f'UPDATE must apply once attribute_exists(flag) holds, got amount={item.get("amount")!r}'
    )

    # attribute_not_exists(flag) does not hold (flag is still present): the UPDATE is refused and
    # the item is left exactly as the previous successful write left it.
    code, msg = _error(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET amount = ? WHERE pk = ? AND attribute_not_exists(flag)',
        Parameters=[{'N': '3'}, {'S': 'p1'}],
    ))
    assert code == ERR_CCF, f'expected {ERR_CCF} when attribute_not_exists(flag) is false, got {code!r}'
    assert msg == MSG_CCF, f"expected AWS's exact message {MSG_CCF!r}, got {msg!r}"
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert item['amount'] == {'N': '2'}, (
        f'a failed conditional UPDATE must leave the item untouched, got amount={item.get("amount")!r}'
    )

    # The same false predicate refuses a DELETE identically, and the item still exists.
    code, msg = _error(lambda: ddb.execute_statement(
        Statement=f'DELETE FROM "{t}" WHERE pk = ? AND attribute_not_exists(flag)',
        Parameters=[{'S': 'p1'}],
    ))
    assert code == ERR_CCF, f'expected {ERR_CCF} when attribute_not_exists(flag) is false, got {code!r}'
    assert msg == MSG_CCF, f"expected AWS's exact message {MSG_CCF!r}, got {msg!r}"
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert item['flag'] == {'S': 'active'}, (
        f'a failed conditional DELETE must leave the item in place, got {item!r}'
    )

    # Remove the attribute so attribute_not_exists(flag) now holds.
    ddb.execute_statement(
        Statement=f'UPDATE "{t}" REMOVE flag WHERE pk = ? AND attribute_exists(flag)',
        Parameters=[{'S': 'p1'}],
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert 'flag' not in item, f'REMOVE flag must drop the attribute, got {item!r}'

    # attribute_not_exists(flag) now holds: the DELETE applies and the item is gone.
    ddb.execute_statement(
        Statement=f'DELETE FROM "{t}" WHERE pk = ? AND attribute_not_exists(flag)',
        Parameters=[{'S': 'p1'}],
    )
    gone = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item')
    assert gone is None, f'DELETE must apply once attribute_not_exists(flag) holds, got {gone!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
