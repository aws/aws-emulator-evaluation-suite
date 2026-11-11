"""number-byte-cost-matches-documented-approximation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "number-byte-cost-matches-documented-approximation"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_MESSAGE = 'Item size has exceeded the maximum allowed size'
_ITEM_LIMIT = 409600

_VALUES = ('0', '1.5', '100.5', '3.14159', '-42', '12345678901234567890')


def _significant_digits(raw: str) -> int:
    """Digit count after the sign, the decimal point and any leading zeroes drop out.

    '0' itself has none. None of the values this check tries has a trailing zero that a
    stricter significant-figure rule would also drop, so this reading needs no such rule.
    """
    digits = raw.lstrip('-').replace('.', '')
    return len(digits.lstrip('0'))


def _approx_cost(digits: int) -> int:
    """The documented approximation: 1 byte per two significant digits, plus 1 byte."""
    return -(-digits // 2) + 1


def _fits(ddb, table, pk, extra) -> bool:
    """PutItem pk with extra merged in; True if accepted, False if rejected for size.

    Any other error is a bug in the check, not an expected outcome, and is left to raise.
    """
    item = {'pk': {'S': pk}}
    item.update(extra)
    try:
        ddb.put_item(TableName=table, Item=item)
        return True
    except ClientError as exc:
        err = exc.response.get('Error', {})
        assert err.get('Code') == ERR_VALIDATION, (
            f'oversized PutItem: expected {ERR_VALIDATION}, got {err.get("Code")}: {err.get("Message")!r}'
        )
        assert err.get('Message') == ERR_MESSAGE, (
            f"oversized PutItem: expected AWS's exact message {ERR_MESSAGE!r}, got {err.get('Message')!r}"
        )
        return False


def _max_filler_len(ddb, table, pk, extra) -> int:
    """The largest filler length (bytes) that keeps pk+extra+filler under the item size limit."""
    lo, hi = 0, _ITEM_LIMIT
    assert _fits(ddb, table, pk, {**extra, 'f': {'S': ''}}), (
        f'{pk}: an empty filler must already fit under {_ITEM_LIMIT} bytes'
    )
    assert not _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * hi}}), (
        f'{pk}: a {hi}-byte filler must already exceed {_ITEM_LIMIT} bytes'
    )
    return _search(ddb, table, pk, extra, lo, hi)


def _search(ddb, table, pk, extra, lo, hi) -> int:
    """Binary search for the largest filler length in [lo, hi], given that lo fits and hi+1 does not."""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * mid}}):
            lo = mid
        else:
            hi = mid - 1
    return lo


def _max_filler_near(ddb, table, pk, extra, guess, slack) -> int:
    """The same boundary as _max_filler_len, searched in guess +/- slack first.

    Two probes bracket the window; only a boundary outside it falls back to the full search, so
    the result is exact either way and a wrong guess costs time, never correctness.
    """
    lo, hi = guess - slack, guess + slack
    if (lo >= 0 and _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * lo}})
            and not _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * (hi + 1)}})):
        return _search(ddb, table, pk, extra, lo, hi)
    return _max_filler_len(ddb, table, pk, extra)


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB Number's byte cost is within one byte of the documented approximation of
    one byte per two significant digits plus one byte, which the docs call approximate, not
    exact -- measured against the 409,600-byte item size ceiling.

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

    # Every trial, including the baseline, writes the SAME pk so the key's own byte cost is
    # identical across them and cancels exactly out of the difference below.
    pk = 'k'
    # The documented item size (attribute names plus values) puts the boundary near the limit less
    # 'pk', 'k' and 'f'; the search is exact wherever it lies.
    baseline = _max_filler_near(ddb, table, pk, {}, _ITEM_LIMIT - len('pkkf'), 64)

    for raw in _VALUES:
        digits = _significant_digits(raw)
        expected = _approx_cost(digits)
        # Searched within a byte of where the documented cost puts the boundary, the window the
        # assert below accepts; a boundary outside it is found by the full search and fails there.
        max_filler = _max_filler_near(
            ddb, table, pk, {'n': {'N': raw}}, baseline - len('n') - expected, 1
        )
        # Adding the 'n' attribute (1-byte name) displaces exactly its own byte cost from the
        # filler budget shared with the baseline under the same item size ceiling.
        measured_cost = baseline - max_filler - len('n')
        # The docs call this "approximately", so the measured cost is graded within a byte of
        # it rather than pinned to an exact undocumented internal encoding.
        assert abs(measured_cost - expected) <= 1, (
            f'N {raw!r} ({digits} significant digits): expected within 1 byte of the documented '
            f'approximation of {expected} bytes, measured {measured_cost} bytes from the '
            f'{_ITEM_LIMIT}-byte boundary'
        )

        # Positive control: the discovered boundary itself is accepted and reads back whole, so
        # a target that silently truncates the filler instead of rejecting it cannot pass here.
        ddb.put_item(TableName=table, Item={
            'pk': {'S': pk}, 'n': {'N': raw}, 'f': {'S': 'x' * max_filler},
        })
        got = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True)['Item']
        assert got['n'] == {'N': raw}, f'{raw!r} must round-trip unchanged at the boundary, got {got["n"]}'
        assert len(got['f']['S']) == max_filler, (
            f'the {max_filler}-byte boundary filler must read back whole, got {len(got["f"]["S"])} bytes'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
