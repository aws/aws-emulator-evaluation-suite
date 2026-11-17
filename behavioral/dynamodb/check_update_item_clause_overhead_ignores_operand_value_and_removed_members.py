"""update-item-clause-overhead-ignores-operand-value-and-removed-members."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'update-item-clause-overhead-ignores-operand-value-and-removed-members'
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_OVER_LIMIT = 'Item size to update has exceeded the maximum allowed size'
_OVER_LIMIT = (ERR_VALIDATION, MSG_OVER_LIMIT)

_KEY = 'pk'
_UPPER_BOUND = 410 * 1024


def _code_and_message(fn):
    """The botocore (code, message) *fn* raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


def _accepted(ddb, table: str, pk: str, base_item: dict, expr: str, values: dict) -> bool:
    """Reset *pk*'s item to *base_item* then attempt one UpdateItem; True if accepted."""
    item = {_KEY: {'S': pk}}
    item.update(base_item)
    ddb.put_item(TableName=table, Item=item)
    try:
        ddb.update_item(
            TableName=table, Key={_KEY: {'S': pk}},
            UpdateExpression=expr, ExpressionAttributeValues=values,
        )
        return True
    except ClientError as exc:
        err = exc.response.get('Error', {})
        if (err.get('Code'), err.get('Message')) == _OVER_LIMIT:
            return False
        raise


def _bisect(ddb, table: str, base_item: dict, expr_fn, pk_source) -> tuple[int, int]:
    """(largest accepted n, smallest refused n) for the clause expr_fn(n) builds, re-verified."""
    lo, hi = 1, _UPPER_BOUND
    while hi - lo > 1:
        mid = (lo + hi) // 2
        expr, values = expr_fn(mid)
        if _accepted(ddb, table, next(pk_source), base_item, expr, values):
            lo = mid
        else:
            hi = mid
    assert hi == lo + 1, f'bisection did not converge to adjacent bytes, got lo={lo} hi={hi}'
    expr, values = expr_fn(lo)
    assert _accepted(ddb, table, next(pk_source), base_item, expr, values), (
        f're-measurement refused the previously-accepted size {lo}'
    )
    expr, values = expr_fn(hi)
    assert not _accepted(ddb, table, next(pk_source), base_item, expr, values), (
        f're-measurement accepted the previously-refused size {hi}'
    )
    return lo, hi


def _plain(n: int) -> tuple[str, dict]:
    return 'SET v = :v', {':v': {'S': 'x' * n}}


def _delete_members(members: list[str]):
    def fn(n: int) -> tuple[str, dict]:
        return ('SET v = :v DELETE s :op',
                {':v': {'S': 'x' * n}, ':op': {'SS': list(members)}})
    return fn


def _copy_path(n: int) -> tuple[str, dict]:
    return 'SET v = :v, c = b', {':v': {'S': 'x' * n}}


def _create_table(ctx, ddb, name: str) -> None:
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': _KEY, 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': _KEY, 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem charges a DELETE clause the same whether it removes a 1-byte, a 200-byte or two
    set members, and a path-operand SET "c = b" charges the same whether b is a 50- or 300-byte
    string or a 50-byte binary value.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-opvalue-')
    _create_table(ctx, ddb, table)
    pk_source = iter(f'{i:08d}' for i in range(1, 1_000_000))

    # DELETE: removing a 1-byte member, a 200-byte member, and two members together all cost
    # the same, once the natural shrinkage from each removal is isolated via a reference item
    # that never had the member(s) in the first place.
    delete_variants = {
        'small': ['a'],
        'large': ['x' * 200],
        'multi': ['a', 'z'],
    }
    delete_overheads: dict[str, int] = {}
    for label, members in delete_variants.items():
        lo_plain_without, _ = _bisect(ddb, table, {}, _plain, pk_source)
        base_with = {'s': {'SS': list(members)}}
        lo_delete, _ = _bisect(ddb, table, base_with, _delete_members(members), pk_source)
        delete_overheads[label] = lo_plain_without - lo_delete
    assert len(set(delete_overheads.values())) == 1, (
        f'DELETE overhead varied with the removed member(s): {delete_overheads!r}'
    )

    # Path operand: once the copied value is large enough that its own bytes dominate, "c = b"
    # charges nothing more as it grows further, and the same whether it is a string or binary
    # value. The reference item already holds c at the value the copy will produce, so only the
    # clause's own request-time charge remains once the cost of duplicating b's value is removed.
    path_variants = {
        'string_50': {'S': 'x' * 50},
        'string_300': {'S': 'x' * 300},
        'binary_50': {'B': b'y' * 50},
    }
    path_overheads: dict[str, int] = {}
    for label, b_value in path_variants.items():
        base_already_copied = {'b': b_value, 'c': b_value}
        lo_plain_already_copied, _ = _bisect(ddb, table, base_already_copied, _plain, pk_source)
        base = {'b': b_value}
        lo_copy, _ = _bisect(ddb, table, base, _copy_path, pk_source)
        path_overheads[label] = lo_plain_already_copied - lo_copy
    assert len(set(path_overheads.values())) == 1, (
        f'path-operand overhead varied with the copied value: {path_overheads!r}'
    )

    # Positive control: the accepted DELETE boundary (small-member variant) actually lands, and
    # the member is actually removed -- proven by a read, not only the absence of a ClientError.
    control_table = ctx.unique_name('sim2real-behav-opvalue-control-')
    _create_table(ctx, ddb, control_table)
    lo, hi = _bisect(ddb, control_table, {'s': {'SS': ['a']}}, _delete_members(['a']), pk_source)

    ddb.put_item(TableName=control_table, Item={_KEY: {'S': 'accepted'}, 's': {'SS': ['a']}})
    expr, values = _delete_members(['a'])(lo)
    ddb.update_item(TableName=control_table, Key={_KEY: {'S': 'accepted'}},
                     UpdateExpression=expr, ExpressionAttributeValues=values)
    stored = ddb.get_item(TableName=control_table, Key={_KEY: {'S': 'accepted'}},
                           ConsistentRead=True).get('Item', {})
    assert 's' not in stored, f'DELETE of the sole member must remove the attribute, got {stored!r}'
    assert len(stored.get('v', {}).get('S', '')) == lo, (
        f'the accepted {lo}-byte update did not read back at that length, got {stored!r}'
    )

    ddb.put_item(TableName=control_table, Item={_KEY: {'S': 'refused'}, 's': {'SS': ['a']}})
    expr_hi, values_hi = _delete_members(['a'])(hi)
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=control_table, Key={_KEY: {'S': 'refused'}},
        UpdateExpression=expr_hi, ExpressionAttributeValues=values_hi,
    ))
    assert (code, message) == _OVER_LIMIT, f'refusal at {hi} bytes was {(code, message)!r}'
    after_refused = ddb.get_item(TableName=control_table, Key={_KEY: {'S': 'refused'}},
                                  ConsistentRead=True).get('Item', {})
    assert after_refused.get('s') == {'SS': ['a']}, (
        f'a refused DELETE must leave the member in place, item is {after_refused!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
