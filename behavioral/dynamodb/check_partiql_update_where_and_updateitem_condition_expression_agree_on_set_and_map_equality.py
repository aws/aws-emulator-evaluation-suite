"""partiql-update-where-and-updateitem-condition-expression-agree-on-set-and-map-equality."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-where-and-updateitem-condition-expression-agree-on-set-and-map-equality"
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
    """An UpdateItem ConditionExpression and a PartiQL UPDATE ... WHERE clause agree on the same '=' predicate over a String Set and a Map.
    A permuted Set still satisfies the condition and the write applies; a mismatched Map does not, and ConditionalCheckFailedException leaves the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlupdwh-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ctx, ddb, table)

    # UpdateItem ConditionExpression 'val = :v': a permuted String Set still satisfies it, and
    # a mismatched one is refused with ConditionalCheckFailedException, item unchanged.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ui_ss'}, 'val': {'SS': ['a', 'b']}})
    ddb.update_item(
        TableName=table, Key={'pk': {'S': 'ui_ss'}},
        UpdateExpression='SET touched = :t',
        ConditionExpression='val = :v',
        ExpressionAttributeValues={':t': {'BOOL': True}, ':v': {'SS': ['b', 'a']}},
    )
    item = ddb.get_item(TableName=table, Key={'pk': {'S': 'ui_ss'}}, ConsistentRead=True)['Item']
    assert item['touched'] == {'BOOL': True}, (
        f"UpdateItem ConditionExpression 'val = :v' with a permuted Set must apply, got {item!r}"
    )

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'ui_ss'}},
        UpdateExpression='SET touched = :t',
        ConditionExpression='val = :v',
        ExpressionAttributeValues={':t': {'BOOL': False}, ':v': {'SS': ['a', 'z']}},
    ))
    assert code == ERR_CCF, f'UpdateItem ConditionExpression with a mismatched Set gave code {code!r}'
    assert msg == MSG_CCF, f'expected the exact message {MSG_CCF!r}, got {msg!r}'
    item = ddb.get_item(TableName=table, Key={'pk': {'S': 'ui_ss'}}, ConsistentRead=True)['Item']
    assert item['touched'] == {'BOOL': True}, (
        f'a refused UpdateItem must leave touched exactly as the prior successful write left it, got {item!r}'
    )

    # The same predicate as a PartiQL UPDATE ... WHERE condition: a permuted Set fires the
    # write (positive control) the same way UpdateItem's ConditionExpression did above.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd_ss'}, 'val': {'SS': ['p', 'q']}})
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET flag = ? WHERE pk = ? AND val = ?',
        Parameters=[{'BOOL': True}, {'S': 'upd_ss'}, {'SS': ['q', 'p']}],
    )
    item = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd_ss'}}, ConsistentRead=True)['Item']
    assert item['flag'] == {'BOOL': True}, (
        f'UPDATE ... WHERE val = <permuted Set> must apply the write, got {item!r}'
    )

    # A matching Map condition applies the write (positive control); a mismatched Map is
    # refused with ConditionalCheckFailedException and leaves the item exactly as that write
    # left it.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd_m'}, 'val': {'M': {'x': {'N': '1'}, 'y': {'S': 'm'}}}})
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET flag = ? WHERE pk = ? AND val = ?',
        Parameters=[{'BOOL': True}, {'S': 'upd_m'}, {'M': {'x': {'N': '1'}, 'y': {'S': 'm'}}}],
    )
    item = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd_m'}}, ConsistentRead=True)['Item']
    assert item['flag'] == {'BOOL': True}, (
        f'positive control: UPDATE ... WHERE val = <matching Map> must apply the write, got {item!r}'
    )

    code, msg = _error(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET flag = ? WHERE pk = ? AND val = ?',
        Parameters=[{'BOOL': False}, {'S': 'upd_m'}, {'M': {'x': {'N': '1'}, 'y': {'S': 'z'}}}],
    ))
    assert code == ERR_CCF, f'UPDATE ... WHERE val = <mismatched Map> gave code {code!r}'
    assert msg == MSG_CCF, f'expected the exact message {MSG_CCF!r}, got {msg!r}'
    item = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd_m'}}, ConsistentRead=True)['Item']
    assert item['flag'] == {'BOOL': True}, (
        f'a refused UPDATE ... WHERE must leave the item exactly as the prior successful write left it, got {item!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
