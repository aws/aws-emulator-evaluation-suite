"""transact-write-items-nesting-violation-is-top-level-validation-not-cancellation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-nesting-violation-is-top-level-validation-not-cancellation"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_CANCELLED = 'TransactionCanceledException'
_NESTING_MESSAGE = (
    'Nesting Levels have exceeded supported limits: Attributes in the item have nested levels '
    'beyond supported limit'
)


def _deep(levels: int) -> dict:
    """A chain of `levels` nested maps around one scalar leaf, `levels` + 1 deep in total."""
    value = {'S': 'leaf'}
    for _ in range(levels):
        value = {'M': {'n': value}}
    return value


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 33-level item in a TransactWriteItems Put, or a 33-level value in its Update SET, is a
    top-level ValidationException for the whole call, never a per-action TransactionCanceledException,
    and neither action's effect lands.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddbtxn-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    deep = _deep(32)  # 33 levels, one past the limit.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'update-target'}, 'ctr': {'N': '1'}})

    # The over-deep item is the Put action; the Update action, on a different item, is itself valid.
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'new-item-via-put'}, 'v': deep}}},
        {'Update': {
            'TableName': t, 'Key': {'pk': {'S': 'update-target'}},
            'UpdateExpression': 'SET ctr = :two',
            'ExpressionAttributeValues': {':two': {'N': '2'}},
        }},
    ]))
    assert code == ERR_VALIDATION, (
        f'a 33-level TransactWriteItems Put must be {ERR_VALIDATION} for the whole call, got '
        f'{code!r}: {message!r}'
    )
    assert code != ERR_CANCELLED, (
        f'nesting-depth validation is a top-level request error, never a per-action cancellation, '
        f'got {code!r}'
    )
    assert message == _NESTING_MESSAGE, f'expected the exact ValidationException message, got {message!r}'
    new_item = ddb.get_item(TableName=t, Key={'pk': {'S': 'new-item-via-put'}}, ConsistentRead=True)
    assert 'Item' not in new_item, (
        f'the over-nested Put must not be written, got {new_item.get("Item")!r}'
    )
    unchanged = ddb.get_item(TableName=t, Key={'pk': {'S': 'update-target'}}, ConsistentRead=True)
    assert unchanged.get('Item', {}).get('ctr') == {'N': '1'}, (
        f"the transaction's own valid Update action must not take effect either, got "
        f'{unchanged.get("Item")!r}'
    )

    # The over-deep value is the Update action's SET; the Put action, on a different item, is valid.
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'new-item-via-sibling-put'}, 'v': {'S': 'fine'}}}},
        {'Update': {
            'TableName': t, 'Key': {'pk': {'S': 'update-target'}},
            'UpdateExpression': 'SET v = :deep',
            'ExpressionAttributeValues': {':deep': deep},
        }},
    ]))
    assert code == ERR_VALIDATION, (
        f'a 33-level TransactWriteItems Update SET must be {ERR_VALIDATION} for the whole call, '
        f'got {code!r}: {message!r}'
    )
    assert code != ERR_CANCELLED, (
        f'nesting-depth validation is a top-level request error, never a per-action cancellation, '
        f'got {code!r}'
    )
    assert message == _NESTING_MESSAGE, f'expected the exact ValidationException message, got {message!r}'
    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'new-item-via-sibling-put'}}, ConsistentRead=True)
    assert 'Item' not in sibling, (
        f"the transaction's own valid Put action must not take effect either, got "
        f'{sibling.get("Item")!r}'
    )
    unchanged = ddb.get_item(TableName=t, Key={'pk': {'S': 'update-target'}}, ConsistentRead=True)
    assert unchanged.get('Item', {}) == {'pk': {'S': 'update-target'}, 'ctr': {'N': '1'}}, (
        f'the over-nested Update must leave the existing item untouched, got {unchanged.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
