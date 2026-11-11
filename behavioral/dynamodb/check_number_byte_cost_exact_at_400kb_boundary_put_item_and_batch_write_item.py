"""number-byte-cost-exact-at-400kb-boundary-put-item-and-batch-write-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "number-byte-cost-exact-at-400kb-boundary-put-item-and-batch-write-item"
GROUP = 'limits'
SERVICES = ['dynamodb']
LIMIT_BYTES = 409600
_SIZE_ERR = ('ValidationException', 'Item size has exceeded the maximum allowed size')

# raw N literal -> its byte cost: 1 + ceil(integer significant digits / 2)
# + ceil(fraction significant digits / 2) + 1 if negative, over the zero-trimmed value,
# with exponent notation counted on the mantissa alone (not expanded).
_PUT_VALUES = (
    ('0', 1),
    ('1', 2),
    ('123', 3),
    ('1234', 3),
    ('123456', 4),
    ('1.5', 3),
    ('3.14159', 5),
    ('0.15', 2),
    ('-42', 3),
    ('1E125', 2),
    ('1E-100', 2),
    ('12345678901234567890123456789012345678', 20),
)
_BATCH_VALUES = (
    ('123456', 4),
    ('1.5', 3),
    ('-42', 3),
    ('1E125', 2),
    ('12345678901234567890123456789012345678', 20),
)


def _canonical_n(raw: str) -> str:
    """The decimal string DynamoDB stores for N literal ``raw``; folds E/e exponent notation."""
    if 'E' not in raw and 'e' not in raw:
        return raw
    mantissa, _, exponent = raw.replace('e', 'E').partition('E')
    exp = int(exponent)
    sign = ''
    if mantissa.startswith('-'):
        sign, mantissa = '-', mantissa[1:]
    int_part, _, frac_part = mantissa.partition('.')
    digits = int_part + frac_part
    point = len(int_part) + exp
    if point <= 0:
        body = '0.' + '0' * (-point) + digits
    elif point >= len(digits):
        body = digits + '0' * (point - len(digits))
    else:
        body = digits[:point] + '.' + digits[point:]
    return sign + body


def _item_of_total_size(pk_value: str, raw: str, cost: int, total_bytes: int) -> dict:
    """A pk + N 'n' (byte cost ``cost``) + filler 'f' item whose aggregate size is exactly total_bytes."""
    overhead = len('pk') + len(pk_value) + len('n') + cost + len('f')
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for an N attribute of cost {cost}'
    return {'pk': {'S': pk_value}, 'n': {'N': raw}, 'f': {'S': 'x' * filler_len}}


def expect_error(fn, code, message) -> None:
    """Assert ``fn`` raises exactly (code, message); an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        assert err.get('Code') == code, (
            f'expected {code}, got {err.get("Code")}: {err.get("Message")!r}'
        )
        assert err.get('Message') == message, (
            f"expected AWS's exact message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number's byte cost at the 400 KB item limit is 1 plus half its zero-trimmed integer and
    fraction significant digits (each rounded up), plus 1 if negative, exponent unexpanded.
    PutItem and BatchWriteItem accept an item sized to exactly that cost and refuse one byte over.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    for i, (raw, cost) in enumerate(_PUT_VALUES):
        expected_n = {'N': _canonical_n(raw)}

        pk_at = f'put-at-{i}'
        at_limit = _item_of_total_size(pk_at, raw, cost, LIMIT_BYTES)
        ddb.put_item(TableName=table, Item=at_limit)
        got = ddb.get_item(TableName=table, Key={'pk': {'S': pk_at}}, ConsistentRead=True)['Item']
        assert got['n'] == expected_n, (
            f'{raw!r} (byte cost {cost}): N must round-trip as {expected_n}, got {got["n"]}'
        )
        assert got['f']['S'] == at_limit['f']['S'], (
            f'{raw!r}: a {LIMIT_BYTES}-byte item built on byte cost {cost} must read back whole'
        )

        pk_over = f'put-over-{i}'
        over = _item_of_total_size(pk_over, raw, cost, LIMIT_BYTES + 1)
        expect_error(lambda over=over: ddb.put_item(TableName=table, Item=over), *_SIZE_ERR)
        rejected = ddb.get_item(TableName=table, Key={'pk': {'S': pk_over}}, ConsistentRead=True)
        assert 'Item' not in rejected, (
            f'{raw!r}: a PutItem rejected for size must not persist, got {rejected.get("Item")}'
        )

    for i, (raw, cost) in enumerate(_BATCH_VALUES):
        expected_n = {'N': _canonical_n(raw)}

        pk_at = f'batch-at-{i}'
        at_limit = _item_of_total_size(pk_at, raw, cost, LIMIT_BYTES)
        resp = ddb.batch_write_item(RequestItems={table: [{'PutRequest': {'Item': at_limit}}]})
        assert resp.get('UnprocessedItems', {}) == {}, (
            f'{raw!r}: a {LIMIT_BYTES}-byte BatchWriteItem PutRequest built on byte cost {cost} '
            f'must fully process, got UnprocessedItems={resp.get("UnprocessedItems")!r}'
        )
        got = ddb.get_item(TableName=table, Key={'pk': {'S': pk_at}}, ConsistentRead=True)['Item']
        assert got['n'] == expected_n, (
            f'{raw!r} (byte cost {cost}): N must round-trip as {expected_n} through '
            f'BatchWriteItem, got {got["n"]}'
        )

        pk_over = f'batch-over-{i}'
        over = _item_of_total_size(pk_over, raw, cost, LIMIT_BYTES + 1)
        expect_error(
            lambda over=over: ddb.batch_write_item(RequestItems={table: [{'PutRequest': {'Item': over}}]}),
            *_SIZE_ERR,
        )
        rejected = ddb.get_item(TableName=table, Key={'pk': {'S': pk_over}}, ConsistentRead=True)
        assert 'Item' not in rejected, (
            f'{raw!r}: a BatchWriteItem PutRequest rejected for size must not persist, '
            f'got {rejected.get("Item")}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
