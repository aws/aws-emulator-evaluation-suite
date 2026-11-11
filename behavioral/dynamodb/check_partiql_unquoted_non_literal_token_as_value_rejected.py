"""partiql-unquoted-non-literal-token-as-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'partiql-unquoted-non-literal-token-as-value-rejected'
GROUP = 'partiql'
SERVICES = ['dynamodb']

#: Bound on the table's CREATING -> ACTIVE transition.
_WAIT_S = 40.0


def _wait_table_active(ddb, table, timeout_s=_WAIT_S) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)['Table']['TableStatus']
        if status == 'ACTIVE':
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f'table {table} not ACTIVE within {timeout_s:.0f}s; last status {status!r}')
        time.sleep(1.0)


def _expect_error(fn, code, message):
    """Call fn() and grade the ClientError it raises against the exact (code, message) pair."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        assert err['Code'] == code, f"expected error code {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        assert err.get('Message') == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return exc
    raise AssertionError(f'expected ({code}, {message!r}), but the call succeeded: {result!r}')


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """An unquoted bareword that is not the true/false/null literal is refused as a value in a
    PartiQL INSERT, leaving the item absent, while true still inserts the same way.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlbw-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ddb, table)

    bad_stmt = f"INSERT INTO \"{table}\" VALUE {{'pk': 'bareword', 'flag': yes}}"
    bad_message = f"Unsupported data type: yes under key root at 1:{bad_stmt.index('yes') + 1}:3"
    _BAREWORD = ('ValidationException', bad_message)
    _expect_error(lambda: ddb.execute_statement(Statement=bad_stmt), *_BAREWORD)

    absent = ddb.get_item(TableName=table, Key={'pk': {'S': 'bareword'}}, ConsistentRead=True).get('Item')
    assert absent is None, f"the refused INSERT left an item behind: {absent!r}"

    ddb.execute_statement(
        Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': 'control', 'flag': true}}"
    )
    control = ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True)['Item']
    assert control == {'pk': {'S': 'control'}, 'flag': {'BOOL': True}}, (
        f"the control INSERT with the true literal stored {control!r}"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
