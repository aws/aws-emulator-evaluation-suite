"""partiql-set-delete-and-parameter-sets."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partiql-set-delete-and-parameter-sets"
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
    """PartiQL set_delete removes a member from a String, Number or Binary Set -- as a literal set
    or with the set passed as a ? parameter -- and deleting the last member removes the attribute
    the same way for every set type; deleting a non-member is a no-op.

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
    ddb.put_item(TableName=t, Item={
        **key,
        'tags': {'SS': ['a', 'b']},
        'nums': {'NS': ['1', '2']},
        'bindata': {'BS': [b'\x01', b'\x02']},
    })

    def _stored():
        return ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']

    # set_delete(tags, <<'a'>>) -- a literal set -- removes one of two String Set members.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = set_delete(tags, <<\'a\'>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert item['tags'] == {'SS': ['b']}, (
        f"set_delete(tags, <<'a'>>) must leave the set {{'b'}}, got {item.get('tags')!r}"
    )

    # set_delete(nums, ?) with the set passed as a parameter removes one of two Number Set members.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET nums = set_delete(nums, ?) WHERE pk = ?',
                           Parameters=[{'NS': ['1']}, {'S': 's1'}])
    item = _stored()
    assert item['nums'] == {'NS': ['2']}, (
        f'set_delete(nums, ?) with {{NS:[1]}} must leave the set {{2}}, got {item.get("nums")!r}'
    )

    # set_add(bindata, ?) with the set passed as a parameter adds a Binary Set member.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET bindata = set_add(bindata, ?) WHERE pk = ?',
                           Parameters=[{'BS': [b'\x03']}, {'S': 's1'}])
    item = _stored()
    assert set(item['bindata']['BS']) == {b'\x01', b'\x02', b'\x03'}, (
        f'set_add(bindata, ?) with {{BS:[\\x03]}} must store {{\\x01,\\x02,\\x03}}, got '
        f'{item.get("bindata")!r}'
    )

    # Deleting a value that is not a member is a no-op: the set is unchanged.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = set_delete(tags, ?) WHERE pk = ?',
                           Parameters=[{'SS': ['not-a-member']}, {'S': 's1'}])
    item = _stored()
    assert item['tags'] == {'SS': ['b']}, (
        f'set_delete of a non-member must leave the set unchanged, got {item.get("tags")!r}'
    )

    # Deleting a String Set's last member removes the attribute entirely.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = set_delete(tags, ?) WHERE pk = ?',
                           Parameters=[{'SS': ['b']}, {'S': 's1'}])
    item = _stored()
    assert 'tags' not in item, f"deleting a Set's last member must remove the attribute, got {item!r}"

    # Deleting a Number Set's last member removes the attribute entirely, the same way.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET nums = set_delete(nums, ?) WHERE pk = ?',
                           Parameters=[{'NS': ['2']}, {'S': 's1'}])
    item = _stored()
    assert 'nums' not in item, f"deleting a Number Set's last member must remove the attribute, got {item!r}"

    # Deleting every remaining Binary Set member removes the attribute entirely, the same way.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET bindata = set_delete(bindata, ?) WHERE pk = ?',
                           Parameters=[{'BS': [b'\x01', b'\x02', b'\x03']}, {'S': 's1'}])
    item = _stored()
    assert 'bindata' not in item, (
        f"deleting a Binary Set's last members must remove the attribute, got {item!r}"
    )
    assert item == {'pk': {'S': 's1'}}, f'only pk must remain on the item, got {item!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
