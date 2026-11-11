"""partiql-true-false-null-literals-are-case-insensitive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'partiql-true-false-null-literals-are-case-insensitive'
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


def _select_pks(ddb, table, where):
    items = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE {where}', ConsistentRead=True
    )['Items']
    return {i['pk']['S'] for i in items}


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """PartiQL INSERT stores the true/False/TRUE and null/Null/NULL literals as BOOL and NULL
    regardless of their case, and a WHERE comparison written in a different case still matches.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlit-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ddb, table)

    # Each pk's INSERT spells its literal in a different case; GetItem proves the stored type.
    bool_items = {
        'flag_true_lower': ('true', {'BOOL': True}),
        'flag_false_mixed': ('False', {'BOOL': False}),
        'flag_true_upper': ('TRUE', {'BOOL': True}),
    }
    null_items = {
        'val_null_lower': 'null',
        'val_null_mixed': 'Null',
        'val_null_upper': 'NULL',
    }

    for pk, (literal, _) in bool_items.items():
        ddb.execute_statement(
            Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': '{pk}', 'flag': {literal}}}"
        )
    for pk, literal in null_items.items():
        ddb.execute_statement(
            Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': '{pk}', 'val': {literal}}}"
        )

    for pk, (literal, expected) in bool_items.items():
        got = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True)['Item']
        assert got['flag'] == expected, (
            f"INSERT with 'flag': {literal} stored flag={got['flag']!r}, expected {expected!r}"
        )

    for pk, literal in null_items.items():
        got = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True)['Item']
        assert got['val'] == {'NULL': True}, (
            f"INSERT with 'val': {literal} stored val={got['val']!r}, expected {{'NULL': True}}"
        )

    true_matched = _select_pks(ddb, table, 'flag = TRUE')
    assert true_matched == {'flag_true_lower', 'flag_true_upper'}, (
        f"WHERE flag = TRUE returned {sorted(true_matched)!r}, expected the two items stored BOOL true"
    )

    false_matched = _select_pks(ddb, table, 'flag = false')
    assert false_matched == {'flag_false_mixed'}, (
        f"WHERE flag = false returned {sorted(false_matched)!r}, expected only the item stored BOOL false"
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
