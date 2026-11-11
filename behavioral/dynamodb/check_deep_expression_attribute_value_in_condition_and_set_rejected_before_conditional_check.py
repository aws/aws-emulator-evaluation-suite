"""deep-expression-attribute-value-in-condition-and-set-rejected-before-conditional-check."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-expression-attribute-value-in-condition-and-set-rejected-before-conditional-check"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_CONDITIONAL = 'ConditionalCheckFailedException'
_NESTING_MESSAGE = (
    '1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in '
    'the item have nested levels beyond supported limit'
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
    """A 33-level ExpressionAttributeValue is rejected ValidationException even where the same
    call's ConditionExpression would otherwise fail, for both PutItem and UpdateItem SET.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddbdeep-')
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

    # The item already exists, so attribute_not_exists(pk) alone would fail the condition --
    # ConditionalCheckFailedException is the outcome if the deep value were valid.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'put-target'}, 'ctr': {'N': '1'}})
    code, message = _error(lambda: ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'put-target'}, 'ctr': {'N': '2'}},
        ConditionExpression='attribute_not_exists(pk) OR ctr = :deep',
        ExpressionAttributeValues={':deep': deep},
    ))
    assert code == ERR_VALIDATION, (
        f'PutItem with a 33-level ExpressionAttributeValue must be {ERR_VALIDATION} even though '
        f'the ConditionExpression would separately fail, got {code!r}: {message!r}'
    )
    assert code != ERR_CONDITIONAL, (
        f'nesting-depth validation must run before the conditional check is evaluated, got {code!r}'
    )
    assert message == _NESTING_MESSAGE, f'expected the exact ValidationException message, got {message!r}'
    unchanged = ddb.get_item(TableName=t, Key={'pk': {'S': 'put-target'}}, ConsistentRead=True)
    assert unchanged.get('Item', {}).get('ctr') == {'N': '1'}, (
        f'the refused PutItem must leave the existing item untouched, got {unchanged.get("Item")!r}'
    )

    # UpdateItem SET writing the same deep value, with a ConditionExpression that would separately
    # fail because the current counter does not equal the sentinel it compares against.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'update-target'}, 'ctr': {'N': '1'}})
    code, message = _error(lambda: ddb.update_item(
        TableName=t,
        Key={'pk': {'S': 'update-target'}},
        UpdateExpression='SET ctr = :deep',
        ConditionExpression='ctr = :mismatch',
        ExpressionAttributeValues={':deep': deep, ':mismatch': {'N': '999'}},
    ))
    assert code == ERR_VALIDATION, (
        f'UpdateItem SET of a 33-level ExpressionAttributeValue must be {ERR_VALIDATION} even '
        f'though the ConditionExpression would separately fail, got {code!r}: {message!r}'
    )
    assert code != ERR_CONDITIONAL, (
        f'nesting-depth validation must run before the conditional check is evaluated, got {code!r}'
    )
    assert message == _NESTING_MESSAGE, f'expected the exact ValidationException message, got {message!r}'
    unchanged = ddb.get_item(TableName=t, Key={'pk': {'S': 'update-target'}}, ConsistentRead=True)
    assert unchanged.get('Item', {}).get('ctr') == {'N': '1'}, (
        f'the refused UpdateItem must leave the existing item untouched, got {unchanged.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
