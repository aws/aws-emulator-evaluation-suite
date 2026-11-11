"""execute-transaction-set-add-commits."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "execute-transaction-set-add-commits"
GROUP = 'partiql'
SERVICES = ['dynamodb']


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A set_add update sent inside ExecuteTransaction commits atomically alongside a sibling
    statement, and a consistent read sees both writes afterward.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html
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

    key1 = {'pk': {'S': 's1'}}
    key2 = {'pk': {'S': 's2'}}
    ddb.put_item(TableName=t, Item=dict(key1))
    ddb.put_item(TableName=t, Item=dict(key2))

    resp = ddb.execute_transaction(TransactStatements=[
        {
            'Statement': f'UPDATE "{t}" SET tags = set_add(tags, <<\'v\'>>) WHERE pk = ?',
            'Parameters': [key1['pk']],
        },
        {
            'Statement': f'UPDATE "{t}" SET note = ? WHERE pk = ?',
            'Parameters': [{'S': 'committed'}, key2['pk']],
        },
    ])
    assert resp['Responses'] == [], (
        f'ExecuteTransaction with no RETURNING clause returns no Responses, got {resp["Responses"]!r}'
    )

    item1 = ddb.get_item(TableName=t, Key=key1, ConsistentRead=True)['Item']
    assert item1.get('tags') == {'SS': ['v']}, (
        f"the transaction's set_add must store {{'SS': ['v']}}, got {item1.get('tags')!r}"
    )
    item2 = ddb.get_item(TableName=t, Key=key2, ConsistentRead=True)['Item']
    assert item2.get('note') == {'S': 'committed'}, (
        f"the sibling statement in the same transaction must also have committed, got {item2.get('note')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
