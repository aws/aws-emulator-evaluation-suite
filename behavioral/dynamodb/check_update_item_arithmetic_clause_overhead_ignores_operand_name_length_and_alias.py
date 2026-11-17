"""update-item-arithmetic-clause-overhead-ignores-operand-name-length-and-alias."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'update-item-arithmetic-clause-overhead-ignores-operand-name-length-and-alias'
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_OVER_LIMIT = 'Item size to update has exceeded the maximum allowed size'
_OVER_LIMIT = (ERR_VALIDATION, MSG_OVER_LIMIT)

_KEY = 'pk'
_UPPER_BOUND = 410 * 1024
_TARGET = 'g'
_SHORT_P, _SHORT_Q = 'p' * 10, 'q' * 10
_LONG_P, _LONG_Q = 'p' * 25, 'q' * 25
_LONG_P_TOKEN, _LONG_Q_TOKEN = '#reallylongaliastoken1', '#reallylongaliastoken2'


def _code_and_message(fn):
    """The botocore (code, message) *fn* raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


def _accepted(ddb, table: str, pk: str, base_item: dict, expr: str, values: dict,
              names: dict | None) -> bool:
    """Reset *pk*'s item to *base_item* then attempt one UpdateItem; True if accepted."""
    item = {_KEY: {'S': pk}}
    item.update(base_item)
    ddb.put_item(TableName=table, Item=item)
    kwargs = {'TableName': table, 'Key': {_KEY: {'S': pk}},
              'UpdateExpression': expr, 'ExpressionAttributeValues': values}
    if names is not None:
        kwargs['ExpressionAttributeNames'] = names
    try:
        ddb.update_item(**kwargs)
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
        expr, values, names = expr_fn(mid)
        if _accepted(ddb, table, next(pk_source), base_item, expr, values, names):
            lo = mid
        else:
            hi = mid
    assert hi == lo + 1, f'bisection did not converge to adjacent bytes, got lo={lo} hi={hi}'
    expr, values, names = expr_fn(lo)
    assert _accepted(ddb, table, next(pk_source), base_item, expr, values, names), (
        f're-measurement refused the previously-accepted size {lo}'
    )
    expr, values, names = expr_fn(hi)
    assert not _accepted(ddb, table, next(pk_source), base_item, expr, values, names), (
        f're-measurement accepted the previously-refused size {hi}'
    )
    return lo, hi


def _plain(n: int) -> tuple[str, dict, None]:
    return 'SET v = :v', {':v': {'S': 'x' * n}}, None


def _add_direct(p_name: str, q_name: str):
    def fn(n: int) -> tuple[str, dict, None]:
        return (f'SET v = :v, {_TARGET} = {p_name} + {q_name}',
                {':v': {'S': 'x' * n}}, None)
    return fn


def _add_alias(p_name: str, q_name: str, p_token: str = '#p', q_token: str = '#q'):
    def fn(n: int) -> tuple[str, dict, dict]:
        return (f'SET v = :v, #g = {p_token} + {q_token}',
                {':v': {'S': 'x' * n}}, {'#g': _TARGET, p_token: p_name, q_token: q_name})
    return fn


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
    """UpdateItem's "g = p + q" byte charge, isolated from the operands' own name bytes, is
    the same for a 10-character and a 25-character operand name, and the same whether an
    operand is named directly, through a short alias, or through a long alias.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-namealias-')
    _create_table(ctx, ddb, table)
    pk_source = iter(f'{i:08d}' for i in range(1, 1_000_000))

    base_short = {_TARGET: {'N': '0'}, _SHORT_P: {'N': '0'}, _SHORT_Q: {'N': '0'}}
    base_long = {_TARGET: {'N': '0'}, _LONG_P: {'N': '0'}, _LONG_Q: {'N': '0'}}

    lo_plain_short, _ = _bisect(ddb, table, base_short, _plain, pk_source)
    lo_plain_long, _ = _bisect(ddb, table, base_long, _plain, pk_source)
    lo_add_direct_short, hi_add_direct_short = _bisect(
        ddb, table, base_short, _add_direct(_SHORT_P, _SHORT_Q), pk_source)
    lo_add_direct_long, _ = _bisect(
        ddb, table, base_long, _add_direct(_LONG_P, _LONG_Q), pk_source)
    lo_add_alias_short, _ = _bisect(
        ddb, table, base_short, _add_alias(_SHORT_P, _SHORT_Q), pk_source)
    lo_add_alias_long, _ = _bisect(
        ddb, table, base_long, _add_alias(_LONG_P, _LONG_Q), pk_source)
    lo_add_long_alias_token, _ = _bisect(
        ddb, table, base_long,
        _add_alias(_LONG_P, _LONG_Q, _LONG_P_TOKEN, _LONG_Q_TOKEN), pk_source)

    overhead_short = lo_plain_short - lo_add_direct_short
    overhead_long = lo_plain_long - lo_add_direct_long
    assert overhead_short == overhead_long, (
        f'addition overhead was {overhead_short} byte(s) for a 10-char operand name but '
        f'{overhead_long} byte(s) for a 25-char operand name'
    )
    assert lo_add_direct_short == lo_add_alias_short, (
        f'naming the operand directly accepted up to {lo_add_direct_short} bytes but an alias '
        f'to the same name accepted up to {lo_add_alias_short}'
    )
    assert lo_add_direct_long == lo_add_alias_long, (
        f'naming the 25-char operand directly accepted up to {lo_add_direct_long} bytes but a '
        f'short alias to the same name accepted up to {lo_add_alias_long}'
    )
    assert lo_add_alias_long == lo_add_long_alias_token, (
        f'a short alias accepted up to {lo_add_alias_long} bytes but a 22-char alias to the '
        f'same real names accepted up to {lo_add_long_alias_token}'
    )

    # Positive control: the accepted boundary for the direct-short addition actually lands, and
    # the next byte up leaves no trace -- proven by a read, not only the absence of a ClientError.
    control_table = ctx.unique_name('sim2real-behav-namealias-control-')
    _create_table(ctx, ddb, control_table)
    expr, values, _ = _add_direct(_SHORT_P, _SHORT_Q)(lo_add_direct_short)
    ddb.put_item(TableName=control_table, Item={_KEY: {'S': 'accepted'}, **base_short})
    ddb.update_item(TableName=control_table, Key={_KEY: {'S': 'accepted'}},
                     UpdateExpression=expr, ExpressionAttributeValues=values)
    stored = ddb.get_item(TableName=control_table, Key={_KEY: {'S': 'accepted'}},
                           ConsistentRead=True).get('Item', {})
    assert len(stored.get('v', {}).get('S', '')) == lo_add_direct_short, (
        f'the accepted {lo_add_direct_short}-byte update did not read back at that length, '
        f'got {stored!r}'
    )

    ddb.put_item(TableName=control_table, Item={_KEY: {'S': 'refused'}, **base_short})
    expr_hi, values_hi, _ = _add_direct(_SHORT_P, _SHORT_Q)(hi_add_direct_short)
    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=control_table, Key={_KEY: {'S': 'refused'}},
        UpdateExpression=expr_hi, ExpressionAttributeValues=values_hi,
    ))
    assert (code, message) == _OVER_LIMIT, (
        f'refusal at {hi_add_direct_short} bytes was {(code, message)!r}, expected {_OVER_LIMIT!r}'
    )
    after_refused = ddb.get_item(TableName=control_table, Key={_KEY: {'S': 'refused'}},
                                  ConsistentRead=True).get('Item', {})
    assert 'v' not in after_refused, f'a refused update must leave no trace, item is {after_refused!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
