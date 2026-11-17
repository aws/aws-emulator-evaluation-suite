"""update-item-addition-and-if-not-exists-overhead-ignores-growth-and-path-absence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'update-item-addition-and-if-not-exists-overhead-ignores-growth-and-path-absence'
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


def _set_to(value: str):
    def fn(n: int) -> tuple[str, dict]:
        return 'SET v = :v, n = :val', {':v': {'S': 'x' * n}, ':val': {'N': value}}
    return fn


def _add(x: str, y: str):
    def fn(n: int) -> tuple[str, dict]:
        return ('SET v = :v, n = :x + :y',
                {':v': {'S': 'x' * n}, ':x': {'N': x}, ':y': {'N': y}})
    return fn


def _if_not_exists_fallback(n: int) -> tuple[str, dict]:
    return ('SET v = :v, f = if_not_exists(f, :fval)',
            {':v': {'S': 'x' * n}, ':fval': {'S': 'a'}})


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
    """UpdateItem's "n = x + y" byte charge depends on the operands' own size, not on the
    arithmetic result's size, even when the result needs one more digit than either operand;
    and if_not_exists charges the same whether its target path already exists or is absent.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-growth-')
    _create_table(ctx, ddb, table)
    pk_source = iter(f'{i:08d}' for i in range(1, 1_000_000))

    base_n_zero = {'n': {'N': '0'}}

    # A plain SET from a 2-digit to a 3-digit number is strictly more expensive -- the
    # bisection resolution can see a 1-digit growth in a stored number.
    lo_plain_2digit, _ = _bisect(ddb, table, base_n_zero, _set_to('98'), pk_source)
    lo_plain_3digit, _ = _bisect(ddb, table, base_n_zero, _set_to('198'), pk_source)
    assert lo_plain_2digit > lo_plain_3digit, (
        f'a plain SET to the 3-digit number did not cost more room than the 2-digit one: '
        f'{lo_plain_2digit} vs {lo_plain_3digit}'
    )

    # "n = x + y" with two 2-digit operands that sum to a 2-digit result (49+49=98) costs the
    # exact same room as the same two 2-digit operands summing to a 3-digit result (99+99=198):
    # the operands are the same size in both calls, and that is what the charge tracks.
    lo_add_no_growth, _ = _bisect(ddb, table, base_n_zero, _add('49', '49'), pk_source)
    lo_add_growth, hi_add_growth = _bisect(ddb, table, base_n_zero, _add('99', '99'), pk_source)
    assert lo_add_no_growth == lo_add_growth, (
        f'"49 + 49" (no digit growth) accepted up to {lo_add_no_growth} bytes but '
        f'"99 + 99" (one extra digit in the result) accepted up to {lo_add_growth}'
    )

    # if_not_exists: creating f via the fallback (path absent) costs the same as leaving an
    # identically-sized f untouched (path present), once the created value matches in size.
    lo_path_present, _ = _bisect(ddb, table, {'f': {'S': 'a'}}, _if_not_exists_fallback, pk_source)
    lo_path_absent, _ = _bisect(ddb, table, {}, _if_not_exists_fallback, pk_source)
    assert lo_path_present == lo_path_absent, (
        f'if_not_exists accepted up to {lo_path_present} bytes when the path already existed '
        f'but only {lo_path_absent} when the fallback had to create it'
    )

    # Positive control: the accepted growing-addition boundary actually lands with n grown to
    # 198, and the refused size leaves n untouched -- proven by a read.
    control_table = ctx.unique_name('sim2real-behav-growth-control-')
    _create_table(ctx, ddb, control_table)

    ddb.put_item(TableName=control_table, Item={_KEY: {'S': 'accepted'}, 'n': {'N': '0'}})
    expr, values = _add('99', '99')(lo_add_growth)
    ddb.update_item(TableName=control_table, Key={_KEY: {'S': 'accepted'}},
                     UpdateExpression=expr, ExpressionAttributeValues=values)
    stored = ddb.get_item(TableName=control_table, Key={_KEY: {'S': 'accepted'}},
                           ConsistentRead=True).get('Item', {})
    assert stored.get('n', {}).get('N') == '198', (
        f'the accepted growing update left n={stored.get("n")!r}, expected N "198"'
    )
    assert len(stored.get('v', {}).get('S', '')) == lo_add_growth, (
        f'the accepted {lo_add_growth}-byte update did not read back at that length, '
        f'got {stored!r}'
    )

    ddb.put_item(TableName=control_table, Item={_KEY: {'S': 'refused'}, 'n': {'N': '0'}})
    expr_hi, values_hi = _add('99', '99')(hi_add_growth)
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=control_table, Key={_KEY: {'S': 'refused'}},
        UpdateExpression=expr_hi, ExpressionAttributeValues=values_hi,
    ))
    assert (code, message) == _OVER_LIMIT, f'refusal at {hi_add_growth} bytes was {(code, message)!r}'
    after_refused = ddb.get_item(TableName=control_table, Key={_KEY: {'S': 'refused'}},
                                  ConsistentRead=True).get('Item', {})
    assert after_refused.get('n') == {'N': '0'}, (
        f'a refused addition must leave n unchanged, item is {after_refused!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
