"""partiql-set-add-on-absent-item-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-set-add-on-absent-item-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']
_CCF = ('ConditionalCheckFailedException', 'The conditional request failed')


def expect_error(fn, code, message):
    """The ``(Code, Message)`` ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response['Error']
        assert error.get('Code') == code, f'expected Code {code!r}, got {error.get("Code")!r}'
        assert error.get('Message') == message, (
            f'expected Message {message!r}, got {error.get("Message")!r}'
        )
        return
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATE ... SET tags = set_add(...) against a primary key with no item raises
    ConditionalCheckFailedException and creates nothing; the identical statement against an
    existing item still succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
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

    statement = f'UPDATE "{t}" SET tags = set_add(tags, <<\'x\'>>) WHERE pk = ?'
    missing_key = {'pk': {'S': 'no-such-item'}}

    # Break exactly one thing: the target key has no item.
    expect_error(
        lambda: ddb.execute_statement(Statement=statement, Parameters=[missing_key['pk']]),
        *_CCF,
    )
    created = ddb.get_item(TableName=t, Key=missing_key, ConsistentRead=True).get('Item')
    assert created is None, (
        f'set_add against an absent item must create nothing, got {created!r}'
    )

    # Positive control: the same statement against an item that exists succeeds.
    existing_key = {'pk': {'S': 'has-item'}}
    ddb.put_item(TableName=t, Item=dict(existing_key))
    ddb.execute_statement(Statement=statement, Parameters=[existing_key['pk']])
    item = ddb.get_item(TableName=t, Key=existing_key, ConsistentRead=True)['Item']
    assert item.get('tags') == {'SS': ['x']}, (
        f"the positive control's set_add must store {{'SS': ['x']}}, got {item.get('tags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
