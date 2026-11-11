"""update-item-set-remove-fixed-action-cost-ceiling."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-remove-fixed-action-cost-ceiling"
GROUP = 'limits'
SERVICES = ['dynamodb']

_OVER_LIMIT = ('ValidationException', 'Item size to update has exceeded the maximum allowed size')
_UPPER_BOUND = 410 * 1024
_FOREIGN_REGION = 'us-east-1'


def _expect_error(fn, code, message) -> None:
    """Call fn(); assert the ClientError it raises is exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        assert err.get('Code') == code, (
            f'expected {code!r}, got {err.get("Code")!r}: {err.get("Message")!r}'
        )
        assert err.get('Message') == message, (
            f'expected message {message!r}, got {err.get("Message")!r}'
        )
        return
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


def _accepted(fn) -> bool:
    """True if fn() (an UpdateItem call) is accepted; False if refused with exactly
    _OVER_LIMIT. Any other outcome fails the check."""
    try:
        fn()
        return True
    except ClientError as exc:
        err = exc.response.get('Error', {})
        pair = (err.get('Code'), err.get('Message'))
        if pair == _OVER_LIMIT:
            return False
        raise AssertionError(f'unexpected error instead of the size refusal: {pair!r}')


def _bisect(accept_fn) -> int:
    """The largest n in [1, _UPPER_BOUND] for which accept_fn(n) is accepted; n+1 is refused."""
    lo, hi = 1, _UPPER_BOUND
    assert accept_fn(lo), f'the smallest probe size {lo} must be accepted'
    assert not accept_fn(hi), f'the largest probe size {hi} must be refused'
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if accept_fn(mid):
            lo = mid
        else:
            hi = mid
    return lo


def _counter():
    return (f'{i:08d}' for i in range(1, 100000))


def _create_table(ctx, ddb, prefix: str) -> str:
    table = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'k', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'k', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda t=table: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})
    return table


def _measure(ddb, table, label: str) -> tuple[int, int, int, int]:
    """The four UpdateItem SET/REMOVE byte ceilings this check compares, for one region."""
    pks = _counter()

    # One SET clause, a 1-character attribute name, on an item that does not have it yet.
    pk1 = next(pks)
    ddb.put_item(TableName=table, Item={'k': {'S': pk1}})
    n_set1 = _bisect(lambda n: _accepted(lambda: ddb.update_item(
        TableName=table, Key={'k': {'S': pk1}},
        UpdateExpression='SET v = :v', ExpressionAttributeValues={':v': {'S': 'x' * n}},
    )))
    # Positive control beside the refusal: the accepted boundary round-trips whole, and the
    # next byte is refused leaving the attribute at its last accepted length.
    ddb.update_item(TableName=table, Key={'k': {'S': pk1}}, UpdateExpression='SET v = :v',
                     ExpressionAttributeValues={':v': {'S': 'x' * n_set1}})
    got = ddb.get_item(TableName=table, Key={'k': {'S': pk1}}, ConsistentRead=True)['Item']
    assert len(got['v']['S']) == n_set1, (
        f'{label}: the accepted {n_set1}-byte SET must round-trip whole, got {len(got["v"]["S"])} bytes'
    )
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={'k': {'S': pk1}}, UpdateExpression='SET v = :v',
        ExpressionAttributeValues={':v': {'S': 'x' * (n_set1 + 1)}},
    ), *_OVER_LIMIT)
    after = ddb.get_item(TableName=table, Key={'k': {'S': pk1}}, ConsistentRead=True)['Item']
    assert len(after['v']['S']) == n_set1, (
        f'{label}: a refused SET must leave the attribute at its last accepted length, '
        f'got {len(after["v"]["S"])} bytes'
    )

    # Two SET clauses: v1 fixed at 1 byte, v2 varied; both attribute names are 2 characters.
    pk2 = next(pks)
    ddb.put_item(TableName=table, Item={'k': {'S': pk2}})
    n_set2 = _bisect(lambda n: _accepted(lambda: ddb.update_item(
        TableName=table, Key={'k': {'S': pk2}},
        UpdateExpression='SET v1 = :v1, v2 = :v2',
        ExpressionAttributeValues={':v1': {'S': 'z'}, ':v2': {'S': 'y' * n}},
    )))

    # One SET plus a REMOVE of a 1-character attribute path that already holds a value.
    pk3 = next(pks)
    ddb.put_item(TableName=table, Item={'k': {'S': pk3}, 'w': {'S': 'present'}})
    n_rm1 = _bisect(lambda n: _accepted(lambda: ddb.update_item(
        TableName=table, Key={'k': {'S': pk3}},
        UpdateExpression='SET v = :v REMOVE w', ExpressionAttributeValues={':v': {'S': 'x' * n}},
    )))
    # Positive control: the REMOVE actually removed w, and v holds the accepted length.
    final = ddb.get_item(TableName=table, Key={'k': {'S': pk3}}, ConsistentRead=True)['Item']
    assert 'w' not in final, f'{label}: REMOVE w must leave no trace, got {sorted(final)!r}'
    assert len(final['v']['S']) == n_rm1, (
        f'{label}: the accepted SET+REMOVE round-trip must store {n_rm1} bytes, got {len(final["v"]["S"])}'
    )

    # One SET plus a REMOVE of a 2-character attribute path, never populated.
    pk4 = next(pks)
    ddb.put_item(TableName=table, Item={'k': {'S': pk4}})
    n_rm2 = _bisect(lambda n: _accepted(lambda: ddb.update_item(
        TableName=table, Key={'k': {'S': pk4}},
        UpdateExpression='SET v = :v REMOVE ww', ExpressionAttributeValues={':v': {'S': 'x' * n}},
    )))

    # A second SET clause adds exactly 19 fixed bytes: 'v1', 'z' and 'v2' together contribute
    # 4 more real content bytes than 'v' alone, so the rest of the n_set1-n_set2 difference is
    # the extra clause's own fixed cost.
    known_extra_content = len('v1') + len('z') + len('v2') - len('v')
    second_set_cost = (n_set1 - n_set2) - known_extra_content
    assert second_set_cost == 19, (
        f'{label}: a second SET clause must add exactly 19 bytes of fixed overhead, measured '
        f'{second_set_cost} (n_set1={n_set1}, n_set2={n_set2})'
    )

    # A REMOVE beside a SET adds exactly one fixed byte plus the removed path's own length,
    # whether or not that path currently holds a value.
    remove_cost_w = n_set1 - n_rm1
    assert remove_cost_w == 1 + len('w'), (
        f"{label}: REMOVE w beside a SET must add exactly {1 + len('w')} bytes, measured {remove_cost_w}"
    )
    remove_cost_ww = n_set1 - n_rm2
    assert remove_cost_ww == 1 + len('ww'), (
        f"{label}: REMOVE ww beside a SET must add exactly {1 + len('ww')} bytes, measured {remove_cost_ww}"
    )

    return n_set1, n_set2, n_rm1, n_rm2


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second SET clause in an UpdateItem adds exactly 19 fixed bytes toward the item-size
    ceiling, and a REMOVE beside a SET adds exactly its path length plus one whether or not the
    path holds a value, with the same byte costs in us-west-2 and us-east-1.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    assert ctx.region != _FOREIGN_REGION, 'the probe needs two distinct regions'
    ddb_home = ctx.client('dynamodb')
    # region-pinned: UpdateItem's fixed per-action byte costs are compared against us-east-1.
    ddb_foreign = ctx.client('dynamodb', region=_FOREIGN_REGION)

    table_home = _create_table(ctx, ddb_home, 'sim2real-behav-ddbcost-home-')
    table_foreign = _create_table(ctx, ddb_foreign, 'sim2real-behav-ddbcost-far-')

    home = _measure(ddb_home, table_home, ctx.region)
    foreign = _measure(ddb_foreign, table_foreign, _FOREIGN_REGION)

    assert home == foreign, (
        f'the fixed per-action byte costs must match between regions, got {ctx.region}={home}, '
        f'{_FOREIGN_REGION}={foreign}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
