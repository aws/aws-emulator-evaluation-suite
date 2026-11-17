"""number-byte-cost-trailing-zero-trim-depends-on-fraction-presence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "number-byte-cost-trailing-zero-trim-depends-on-fraction-presence"
GROUP = 'limits'
SERVICES = ['dynamodb']
LIMIT_BYTES = 409600
_SIZE_ERR = ('ValidationException', 'Item size has exceeded the maximum allowed size')

# raw N literal -> its byte cost at the 409,600-byte item size gate.
_VALUES = (
    ('100', 2),    # bare integer: the trailing zeros trim away, one significant digit left
    ('1010', 3),   # bare integer: only the single trailing zero trims, three digits left
    ('12', 2),     # bare integer, no trailing zero to trim
    ('15', 2),     # bare integer, no trailing zero to trim
    ('100.5', 4),  # a fraction is present, so the integer part keeps its trailing zeros
)


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


def _item_of_total_size(pk_value: str, raw: str, cost: int, total_bytes: int) -> dict:
    """A pk + N 'n' (byte cost ``cost``) + filler 'f' item whose aggregate size is exactly total_bytes."""
    overhead = len('pk') + len(pk_value) + len('n') + cost + len('f')
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for an N attribute of cost {cost}'
    return {'pk': {'S': pk_value}, 'n': {'N': raw}, 'f': {'S': 'x' * filler_len}}


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number's byte cost at the 400 KB item limit trims a bare integer's trailing zeros, but
    keeps the integer part's trailing zeros once the literal also carries a fraction. PutItem
    accepts an item sized to exactly that cost and refuses one byte over.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
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

    for i, (raw, cost) in enumerate(_VALUES):
        expected_n = {'N': raw}

        pk_at = f'at-{i}'
        at_limit = _item_of_total_size(pk_at, raw, cost, LIMIT_BYTES)
        ddb.put_item(TableName=table, Item=at_limit)
        got = ddb.get_item(TableName=table, Key={'pk': {'S': pk_at}}, ConsistentRead=True)['Item']
        assert got['n'] == expected_n, (
            f'{raw!r} (byte cost {cost}): N must round-trip as {expected_n}, got {got["n"]}'
        )
        assert got['f']['S'] == at_limit['f']['S'], (
            f'{raw!r}: a {LIMIT_BYTES}-byte item built on byte cost {cost} must read back whole'
        )

        pk_over = f'over-{i}'
        over = _item_of_total_size(pk_over, raw, cost, LIMIT_BYTES + 1)
        expect_error(lambda over=over: ddb.put_item(TableName=table, Item=over), *_SIZE_ERR)
        rejected = ddb.get_item(TableName=table, Key={'pk': {'S': pk_over}}, ConsistentRead=True)
        assert 'Item' not in rejected, (
            f'{raw!r}: a PutItem rejected for size must not persist, got {rejected.get("Item")}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
