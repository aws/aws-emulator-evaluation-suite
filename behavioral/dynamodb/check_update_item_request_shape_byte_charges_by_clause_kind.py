"""update-item-request-shape-byte-charges-by-clause-kind."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-request-shape-byte-charges-by-clause-kind"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_OVER_LIMIT = 'Item size to update has exceeded the maximum allowed size'
_OVER_LIMIT = (ERR_VALIDATION, MSG_OVER_LIMIT)

_KEY = 'pk'
_UPPER_BOUND = 410 * 1024

# Each family: the attributes a fresh item needs before the update, and a builder from
# a baseline value length n to (UpdateExpression, ExpressionAttributeValues). Every
# family's non-baseline operand is chosen so an accepted update leaves its own stored
# bytes unchanged (0 + 0, if_not_exists over an attribute that already exists, an
# ADD/DELETE operand that is already a no-op): any boundary shift relative to a plain
# SET comes only from the clause's own request shape, never from the finished item
# growing or shrinking.
_FAMILIES = {
    'path_operand': ({}, lambda n: ('SET v = :v', {':v': {'S': 'x' * n}})),
    'document_path': ({'m': {'M': {'x': {'S': 'a'}}}},
                       lambda n: ('SET v = :v, m.x = :mval',
                                  {':v': {'S': 'x' * n}, ':mval': {'S': 'a'}})),
    'arithmetic': ({'n': {'N': '0'}},
                   lambda n: ('SET v = :v, n = n + :one',
                              {':v': {'S': 'x' * n}, ':one': {'N': '0'}})),
    'function': ({'f': {'S': 'a'}},
                 lambda n: ('SET v = :v, f = if_not_exists(f, :fval)',
                            {':v': {'S': 'x' * n}, ':fval': {'S': 'a'}})),
    'add': ({'c': {'N': '0'}},
            lambda n: ('SET v = :v ADD c :zero',
                       {':v': {'S': 'x' * n}, ':zero': {'N': '0'}})),
    'remove_delete': ({'s': {'SS': ['a']}},
                       lambda n: ('SET v = :v DELETE s :absent',
                                  {':v': {'S': 'x' * n}, ':absent': {'SS': ['q']}})),
}

# Bytes of accepted-size shortfall relative to the plain-SET baseline, identical in
# us-west-2 and us-east-1: the charge differs by clause kind.
_EXPECTED_DELTA_FROM_BASELINE = {
    'path_operand': 0,
    'document_path': 26,
    'arithmetic': 71,
    'function': 76,
    'add': 21,
    'remove_delete': 2,
}


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
    """(largest accepted n, smallest refused n) for the clause expr_fn(n) builds."""
    lo, hi = 1, _UPPER_BOUND
    while hi - lo > 1:
        mid = (lo + hi) // 2
        expr, values = expr_fn(mid)
        if _accepted(ddb, table, next(pk_source), base_item, expr, values):
            lo = mid
        else:
            hi = mid
    return lo, hi


def _measure(ddb, table: str, pk_source) -> dict[str, tuple[int, int]]:
    """Bisected (lo, hi) boundary per family, each re-verified once for stability."""
    boundaries: dict[str, tuple[int, int]] = {}
    for label, (base_item, expr_fn) in _FAMILIES.items():
        lo, hi = _bisect(ddb, table, base_item, expr_fn, pk_source)
        assert hi == lo + 1, f'{label}: bisection did not converge to adjacent bytes, got lo={lo} hi={hi}'
        boundaries[label] = (lo, hi)
    for label, (base_item, expr_fn) in _FAMILIES.items():
        lo, hi = boundaries[label]
        assert _accepted(ddb, table, next(pk_source), base_item, *expr_fn(lo)), (
            f'{label}: re-measurement refused the previously-accepted size {lo}'
        )
        assert not _accepted(ddb, table, next(pk_source), base_item, *expr_fn(hi)), (
            f'{label}: re-measurement accepted the previously-refused size {hi}'
        )
    return boundaries


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
    """UpdateItem's size limit charges each SET/ADD/DELETE clause's own request shape,
    not only the bytes the finished item occupies, and the per-clause-kind shortfall
    from a flat 400 KB boundary is identical in us-west-2 and us-east-1.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb_west = ctx.client('dynamodb')
    # region-pinned: UpdateItem's per-clause size accounting is compared against us-east-1.
    ddb_east = ctx.client('dynamodb', region='us-east-1')

    boundaries_by_region: dict[str, dict[str, tuple[int, int]]] = {}
    for region_label, ddb in (('us-west-2', ddb_west), ('us-east-1', ddb_east)):
        table = ctx.unique_name('sim2real-behav-reqshape-')
        _create_table(ctx, ddb, table)
        pk_source = iter(f'{i:08d}' for i in range(1, 1_000_000))
        boundaries_by_region[region_label] = _measure(ddb, table, pk_source)

    for fam in _FAMILIES:
        west, east = boundaries_by_region['us-west-2'][fam], boundaries_by_region['us-east-1'][fam]
        assert west == east, f'{fam}: us-west-2 boundary {west!r} differs from us-east-1 boundary {east!r}'

    base_lo = boundaries_by_region['us-west-2']['path_operand'][0]
    for fam, expected_delta in _EXPECTED_DELTA_FROM_BASELINE.items():
        lo = boundaries_by_region['us-west-2'][fam][0]
        delta = base_lo - lo
        assert delta == expected_delta, (
            f'{fam}: measured {delta} byte(s) of request-shape charge relative to a plain SET, '
            f'expected {expected_delta}'
        )

    # Positive control: the accepted boundary for the plain SET actually lands, and the
    # next byte up actually leaves no trace -- proven by a read, not only by the
    # absence of a ClientError.
    control_table = ctx.unique_name('sim2real-behav-reqshape-control-')
    _create_table(ctx, ddb_west, control_table)
    lo, hi = boundaries_by_region['us-west-2']['path_operand']

    ddb_west.put_item(TableName=control_table, Item={_KEY: {'S': 'accepted'}})
    ddb_west.update_item(
        TableName=control_table, Key={_KEY: {'S': 'accepted'}},
        UpdateExpression='SET v = :v', ExpressionAttributeValues={':v': {'S': 'x' * lo}},
    )
    stored = ddb_west.get_item(
        TableName=control_table, Key={_KEY: {'S': 'accepted'}}, ConsistentRead=True,
    ).get('Item', {})
    assert len(stored.get('v', {}).get('S', '')) == lo, (
        f'the accepted {lo}-byte SET did not read back at that length, got {stored!r}'
    )

    ddb_west.put_item(TableName=control_table, Item={_KEY: {'S': 'refused'}})
    code, message = _code_and_message(lambda: ddb_west.update_item(
        TableName=control_table, Key={_KEY: {'S': 'refused'}},
        UpdateExpression='SET v = :v', ExpressionAttributeValues={':v': {'S': 'x' * hi}},
    ))
    assert (code, message) == _OVER_LIMIT, f'refusal at {hi} bytes was {(code, message)!r}, expected {_OVER_LIMIT!r}'
    after_refused = ddb_west.get_item(
        TableName=control_table, Key={_KEY: {'S': 'refused'}}, ConsistentRead=True,
    ).get('Item', {})
    assert 'v' not in after_refused, f'a refused SET must leave no trace, item is {after_refused!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
