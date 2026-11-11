"""bool-and-null-attribute-byte-cost-at-item-size-gate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'bool-and-null-attribute-byte-cost-at-item-size-gate'
GROUP = 'limits'
SERVICES = ['dynamodb']
_ITEM_LIMIT = 409600
_REFUSAL = ('ValidationException', 'Item size has exceeded the maximum allowed size')
_PK = 'k'


def expect_error(fn, code, message):
    """Call fn() and assert the ClientError it raises carries exactly code and message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        assert err.get('Code') == code, f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        assert err.get('Message') == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return exc
    raise AssertionError(f'expected {code!r}, but the call succeeded: {result!r}')


def _fits(ddb, table, pk, extra) -> bool:
    """PutItem of {pk} merged with extra; True if accepted, False if refused for size."""
    item = {'pk': {'S': pk}}
    item.update(extra)
    try:
        ddb.put_item(TableName=table, Item=item)
        return True
    except ClientError as exc:
        err = exc.response.get('Error', {})
        assert err.get('Code') == _REFUSAL[0], (
            f'oversized PutItem: expected {_REFUSAL[0]}, got {err.get("Code")}: {err.get("Message")!r}'
        )
        assert err.get('Message') == _REFUSAL[1], (
            f"oversized PutItem: expected AWS's exact message {_REFUSAL[1]!r}, got {err.get('Message')!r}"
        )
        return False


def _max_filler_near(ddb, table, pk, extra, guess, slack) -> int:
    """The largest filler length (bytes) for which {pk, **extra, f: filler} still fits.

    Two probes bracket the window at guess +/- slack; only a boundary outside it falls back to a
    full search, so the result is exact either way.
    """
    lo, hi = guess - slack, guess + slack
    if (lo >= 0 and _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * lo}})
            and not _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * (hi + 1)}})):
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * mid}}):
                lo = mid
            else:
                hi = mid - 1
        return lo
    lo, hi = 0, _ITEM_LIMIT
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _fits(ddb, table, pk, {**extra, 'f': {'S': 'x' * mid}}):
            lo = mid
        else:
            hi = mid - 1
    return lo


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem bills a BOOL or a NULL attribute at its name's byte length plus exactly one byte
    toward the 409,600-byte item size ceiling, for both BOOL values and for NULL.

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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    # Every cost trial, including the baseline, writes the SAME pk so the key's own byte cost is
    # identical across them and cancels exactly out of the difference below.
    baseline = _max_filler_near(ddb, table, _PK, {}, _ITEM_LIMIT - len('pkkf'), 8)

    cases = [
        ('b', {'BOOL': True}),
        ('b', {'BOOL': False}),
        ('z', {'NULL': True}),
    ]
    for name, value in cases:
        # Searched within the window the extra attribute's 1-byte expected cost puts the boundary
        # at; a boundary outside it is found by the full search and fails there regardless.
        max_filler = _max_filler_near(ddb, table, _PK, {name: value}, baseline - len(name) - 1, 4)
        measured_cost = baseline - max_filler - len(name)
        assert measured_cost == 1, (
            f'{name}={value!r}: expected exactly 1 byte of value cost, measured {measured_cost} bytes '
            f'from the {_ITEM_LIMIT}-byte boundary'
        )

    # The item-size gate itself, built with a BOOL attribute present. "acc-bool" and "rej-bool"
    # are the same length, so the boundary found for one is exactly the boundary for the other.
    bool_filler = _max_filler_near(ddb, table, 'acc-bool', {'b': {'BOOL': True}}, baseline - len('b') - 1, 4)
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'acc-bool'}, 'b': {'BOOL': True}, 'f': {'S': 'x' * bool_filler},
    })
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'acc-bool'}}, ConsistentRead=True)['Item']
    assert got['b'] == {'BOOL': True}, f"the accepted boundary item's BOOL attribute read back {got['b']!r}"
    assert len(got['f']['S']) == bool_filler, (
        f"the accepted boundary item's filler read back {len(got['f']['S'])} bytes, expected {bool_filler}"
    )

    # One byte over the same boundary is refused with the exact code and message, and the
    # rejected write leaves no item behind at a key never written before.
    expect_error(
        lambda: ddb.put_item(TableName=table, Item={
            'pk': {'S': 'rej-bool'}, 'b': {'BOOL': True}, 'f': {'S': 'x' * (bool_filler + 1)},
        }),
        *_REFUSAL,
    )
    rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'rej-bool'}}, ConsistentRead=True)
    assert 'Item' not in rejected, f'the refused over-limit PutItem must not persist, got {rejected.get("Item")}'

    # The same boundary demonstrated with a NULL attribute instead of BOOL.
    null_filler = _max_filler_near(ddb, table, 'acc-null', {'z': {'NULL': True}}, baseline - len('z') - 1, 4)
    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'acc-null'}, 'z': {'NULL': True}, 'f': {'S': 'x' * null_filler},
    })
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'acc-null'}}, ConsistentRead=True)['Item']
    assert got['z'] == {'NULL': True}, f"the accepted boundary item's NULL attribute read back {got['z']!r}"

    expect_error(
        lambda: ddb.put_item(TableName=table, Item={
            'pk': {'S': 'rej-null'}, 'z': {'NULL': True}, 'f': {'S': 'x' * (null_filler + 1)},
        }),
        *_REFUSAL,
    )
    rejected = ddb.get_item(TableName=table, Key={'pk': {'S': 'rej-null'}}, ConsistentRead=True)
    assert 'Item' not in rejected, f'the refused over-limit PutItem must not persist, got {rejected.get("Item")}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
