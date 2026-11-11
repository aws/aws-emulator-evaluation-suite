"""partiql-relational-operators-reject-complex-type-operands."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-relational-operators-reject-complex-type-operands"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_LEGS = [
    ('<', 'L', 'val < [1, 2]'),
    ('<=', 'M', "val <= {'x': 1}"),
    ('>', 'SS', "val > <<'a', 'b'>>"),
    ('>=', 'BOOL', 'val >= true'),
    ('BETWEEN', 'NULL', 'val BETWEEN NULL AND 5'),
]


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS raises, since an emulator
    accepting a comparison real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the statement to be rejected, but it SUCCEEDED with {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each relational comparator (<, <=, >, >=, BETWEEN) rejects a List, Map, String Set,
    Boolean or Null literal operand with ValidationException, and a rejected UPDATE/DELETE
    WHERE clause writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlrel-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    item = {'pk': {'S': 'item'}, 'val': {'N': '5'}}
    ddb.put_item(TableName=table, Item=item)

    # Positive control: the same comparator over two comparable numbers succeeds, so a rejection
    # below is attributable to the operand's type, not to '<' itself being broken.
    control = ddb.execute_statement(Statement=f'SELECT * FROM "{table}" WHERE val < 10', ConsistentRead=True)
    assert control['Items'] == [item], f'positive control returned {control["Items"]!r}, expected [{item!r}]'

    for op, typ, clause in _LEGS:
        code, message = _error(
            lambda clause=clause: ddb.execute_statement(Statement=f'SELECT * FROM "{table}" WHERE {clause}')
        )
        assert code == 'ValidationException', f'{op} against a {typ} operand gave code {code!r}'
        expected = (
            f'Incorrect operand type for operator or function; operator or function: {op}, '
            f'operand type: {typ}'
        )
        assert message == expected, f'{op} against a {typ} operand: expected message {expected!r}, got {message!r}'

    # A rejected WHERE clause in UPDATE and DELETE statements writes nothing: the item comes
    # back exactly as stored, with no attribute added and no deletion performed.
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET other = 1 WHERE pk = \'item\' AND val < [1, 2]'
    ))
    assert code == 'ValidationException', f'UPDATE with a rejected WHERE clause gave code {code!r}'
    expected = 'Incorrect operand type for operator or function; operator or function: <, operand type: L'
    assert message == expected, f'UPDATE: expected message {expected!r}, got {message!r}'

    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'DELETE FROM "{table}" WHERE pk = \'item\' AND val <= true'
    ))
    assert code == 'ValidationException', f'DELETE with a rejected WHERE clause gave code {code!r}'
    expected = 'Incorrect operand type for operator or function; operator or function: <=, operand type: BOOL'
    assert message == expected, f'DELETE: expected message {expected!r}, got {message!r}'

    after = ddb.get_item(TableName=table, Key={'pk': {'S': 'item'}}, ConsistentRead=True)['Item']
    assert after == item, f'item must be unchanged after both rejected statements, got {after!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
