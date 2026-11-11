"""batch-execute-statement-set-add-no-error-slot."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-execute-statement-set-add-no-error-slot"
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
    """A set_add UPDATE sent as a BatchExecuteStatement member creates the string set on the
    item, and its slot in Responses carries no Error.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
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

    key = {'pk': {'S': 's1'}}
    ddb.put_item(TableName=t, Item=dict(key))

    resp = ddb.batch_execute_statement(Statements=[
        {
            'Statement': f'UPDATE "{t}" SET tags = set_add(tags, <<\'w\'>>) WHERE pk = ?',
            'Parameters': [key['pk']],
        },
    ])
    responses = resp['Responses']
    assert len(responses) == 1, f'expected one per-statement response, got {len(responses)}: {responses!r}'
    assert 'Error' not in responses[0], (
        f'a successful set_add batch member must carry no Error, got {responses[0]!r}'
    )

    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert item.get('tags') == {'SS': ['w']}, (
        f"the batch member's set_add must store {{'SS': ['w']}}, got {item.get('tags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
