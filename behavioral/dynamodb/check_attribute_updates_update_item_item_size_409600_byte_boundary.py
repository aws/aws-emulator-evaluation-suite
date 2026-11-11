"""attribute-updates-update-item-item-size-409600-byte-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-updates-update-item-item-size-409600-byte-boundary"
GROUP = 'limits'
SERVICES = ['dynamodb']
LIMIT_BYTES = 409600
_PK = 'k'
_ATTR = 'data'
_OVER_LIMIT = ('ValidationException', 'Item size to update has exceeded the maximum allowed size')


def _filler(total_bytes: int) -> str:
    """An ASCII filler for ``_ATTR`` making the whole item exactly ``total_bytes``."""
    overhead = len('pk'.encode()) + len(_PK.encode()) + len(_ATTR.encode())
    filler_len = total_bytes - overhead
    assert filler_len > 0, f'{total_bytes} bytes is too small for this item shape'
    return 'x' * filler_len


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response['Error'].get('Code'), exc.response['Error'].get('Message'))
        assert got == (code, message), f'expected {(code, message)!r}, got {got!r}'
        return
    raise AssertionError(f'expected {code} but the call succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's legacy AttributeUpdates grows an item to exactly the 409,600-byte limit
    and reads back whole; one byte more is refused and the stored item is unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
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

    at_limit = _filler(LIMIT_BYTES)
    ddb.update_item(
        TableName=table,
        Key={'pk': {'S': _PK}},
        AttributeUpdates={_ATTR: {'Value': {'S': at_limit}, 'Action': 'PUT'}},
    )
    got = ddb.get_item(TableName=table, Key={'pk': {'S': _PK}}, ConsistentRead=True).get('Item') or {}
    stored = got.get(_ATTR, {}).get('S', '')
    assert stored == at_limit, (
        f'a legacy AttributeUpdates PUT growing the item to exactly {LIMIT_BYTES} bytes must round-trip '
        f'whole, got {len(stored)} bytes back'
    )

    over = _filler(LIMIT_BYTES + 1)
    expect_error(
        lambda: ddb.update_item(
            TableName=table,
            Key={'pk': {'S': _PK}},
            AttributeUpdates={_ATTR: {'Value': {'S': over}, 'Action': 'PUT'}},
        ),
        *_OVER_LIMIT,
    )
    unchanged = ddb.get_item(TableName=table, Key={'pk': {'S': _PK}}, ConsistentRead=True).get('Item') or {}
    assert unchanged.get(_ATTR, {}).get('S', '') == at_limit, (
        f'a legacy AttributeUpdates PUT refused for growing the item to {LIMIT_BYTES + 1} bytes '
        f'must leave the stored {LIMIT_BYTES}-byte value unchanged'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
