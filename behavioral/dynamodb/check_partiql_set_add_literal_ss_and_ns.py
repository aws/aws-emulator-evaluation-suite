"""partiql-set-add-literal-ss-and-ns."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partiql-set-add-literal-ss-and-ns"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL UPDATE ... SET s = set_add(s, <<...>>) on a String Set and a Number Set stores the
    union after each call, and adding a member already present leaves the set unchanged.

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

    key = {'pk': {'S': 's1'}}
    ddb.execute_statement(
        Statement=f'INSERT INTO "{t}" VALUE {{\'pk\': ?, \'tags\': ?, \'nums\': ?}}',
        Parameters=[{'S': 's1'}, {'SS': ['a']}, {'NS': ['10']}],
    )

    def _stored():
        return ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']

    # set_add(tags, <<'b'>>) on a String Set adds the new member.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = set_add(tags, <<\'b\'>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert set(item['tags']['SS']) == {'a', 'b'}, (
        f"set_add(tags, <<'b'>>) must store {{'a','b'}}, got {item.get('tags')!r}"
    )

    # Adding a member already present is a no-op: the stored set is unchanged.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = set_add(tags, <<\'b\'>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert set(item['tags']['SS']) == {'a', 'b'}, (
        f"re-adding the already-present member 'b' must leave the set unchanged, got {item.get('tags')!r}"
    )

    # set_add(nums, <<20>>) on a Number Set adds the new member.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET nums = set_add(nums, <<20>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert set(item['nums']['NS']) == {'10', '20'}, (
        f'set_add(nums, <<20>>) must store {{10,20}}, got {item.get("nums")!r}'
    )

    # Adding an already-present numeric member is likewise a no-op.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET nums = set_add(nums, <<20>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert set(item['nums']['NS']) == {'10', '20'}, (
        f're-adding the already-present member 20 must leave the set unchanged, got {item.get("nums")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
