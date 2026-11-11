"""partiql-set-add-set-delete-accepted-forms."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partiql-set-add-set-delete-accepted-forms"
GROUP = 'partiql'
SERVICES = ['dynamodb']


def _as_set(attr):
    """A Set attribute ``{'SS': [...]}``/``{'NS': [...]}`` as ``(type, frozenset(members))``.

    DynamoDB does not document member order for a Set, so every multi-member comparison here
    goes through this normal form instead of comparing the raw list.
    """
    (vtype, members), = attr.items()
    return vtype, frozenset(members)


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
    """set_add on an absent attribute creates the set; set_delete on an absent one is a no-op.
    SET_ADD is case-insensitive, two SET clauses can each call set_add, and RETURNING ALL NEW *
    then returns their union; SET a = <<'x','y'>> assigns a string set from a literal directly.

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
    ddb.put_item(TableName=t, Item=dict(key))

    def _stored():
        return ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']

    # 1. set_add(tags, <<'x'>>) on an attribute that does not yet exist creates the set.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = set_add(tags, <<\'x\'>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert _as_set(item['tags']) == ('SS', frozenset({'x'})), (
        f"set_add on the absent attribute 'tags' must create {{'SS': ['x']}}, got {item.get('tags')!r}"
    )

    # 2. set_delete on an attribute that still does not exist leaves it absent, no-op.
    ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET absentattr = set_delete(absentattr, <<\'x\'>>) WHERE pk = ?',
        Parameters=[{'S': 's1'}])
    item = _stored()
    assert 'absentattr' not in item, (
        f"set_delete on the absent attribute 'absentattr' must leave it absent, got {item!r}"
    )
    assert _as_set(item['tags']) == ('SS', frozenset({'x'})), (
        f"the unrelated attribute 'tags' must be unchanged by the set_delete no-op, got {item.get('tags')!r}"
    )

    # 3. SET_ADD (uppercase) is the same function as set_add: case-insensitive.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET tags = SET_ADD(tags, <<\'y\'>>) WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert _as_set(item['tags']) == ('SS', frozenset({'x', 'y'})), (
        f"SET_ADD (uppercase) must behave as set_add and store {{'SS': ['x','y']}}, got {item.get('tags')!r}"
    )

    # 4. Two SET clauses in one statement can each call set_add, and RETURNING ALL NEW * returns
    #    the post-update item with both attributes at their unioned values.
    resp = ddb.execute_statement(
        Statement=(
            f'UPDATE "{t}" SET tags = set_add(tags, <<\'z\'>>) SET nums = set_add(nums, <<5>>) '
            f'WHERE pk = ? RETURNING ALL NEW *'
        ),
        Parameters=[{'S': 's1'}])
    assert len(resp['Items']) == 1, f'RETURNING ALL NEW * must return exactly one item, got {resp["Items"]!r}'
    returned = resp['Items'][0]
    assert returned['pk'] == {'S': 's1'}, f'returned item must keep the key, got {returned!r}'
    assert _as_set(returned['tags']) == ('SS', frozenset({'x', 'y', 'z'})), (
        f"RETURNING ALL NEW * after two SET clauses must return tags as the union {{'x','y','z'}}, "
        f"got {returned.get('tags')!r}"
    )
    assert _as_set(returned['nums']) == ('NS', frozenset({'5'})), (
        f"RETURNING ALL NEW * after two SET clauses must return nums {{'NS': ['5']}}, "
        f"got {returned.get('nums')!r}"
    )
    item = _stored()
    assert item['pk'] == {'S': 's1'}, f'stored item must keep the key, got {item!r}'
    assert _as_set(item['tags']) == ('SS', frozenset({'x', 'y', 'z'})), (
        f"the stored tags after both set_add calls must be the union {{'x','y','z'}}, "
        f"got {item.get('tags')!r}"
    )
    assert _as_set(item['nums']) == ('NS', frozenset({'5'})), (
        f"the stored nums after both set_add calls must be {{'NS': ['5']}}, got {item.get('nums')!r}"
    )

    # 5. SET a = <<'x','y'>> assigns a literal set directly, creating a String Set with no function.
    ddb.execute_statement(Statement=f'UPDATE "{t}" SET lit = <<\'x\', \'y\'>> WHERE pk = ?',
                           Parameters=[{'S': 's1'}])
    item = _stored()
    assert _as_set(item['lit']) == ('SS', frozenset({'x', 'y'})), (
        f"SET lit = <<'x','y'>> must store a String Set {{'SS': ['x','y']}}, got {item.get('lit')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
