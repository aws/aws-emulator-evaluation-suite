"""batch-write-item-rejects-whole-call-for-one-oversized-nested-put."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-rejects-whole-call-for-one-oversized-nested-put"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
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
    """BatchWriteItem refuses the whole call ValidationException when one PutRequest nests 33
    levels deep, and the request's valid sibling PutRequest is not written either.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddbbatch-')
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
    code, message = _error(lambda: ddb.batch_write_item(RequestItems={t: [
        {'PutRequest': {'Item': {'pk': {'S': 'ok-sibling'}, 'v': {'S': 'fine'}}}},
        {'PutRequest': {'Item': {'pk': {'S': 'too-deep'}, 'v': deep}}},
    ]}))
    assert code == ERR_VALIDATION, (
        f'a BatchWriteItem call with one 33-level item must be {ERR_VALIDATION} for the whole '
        f'call, got {code!r}: {message!r}'
    )
    assert message == _NESTING_MESSAGE, f'expected the exact ValidationException message, got {message!r}'

    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'ok-sibling'}}, ConsistentRead=True)
    assert 'Item' not in sibling, (
        f'the request is rejected as a whole, so the valid sibling PutRequest must not be '
        f'written, got {sibling.get("Item")!r}'
    )
    deep_item = ddb.get_item(TableName=t, Key={'pk': {'S': 'too-deep'}}, ConsistentRead=True)
    assert 'Item' not in deep_item, (
        f'the over-nested PutRequest must not be written, got {deep_item.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
