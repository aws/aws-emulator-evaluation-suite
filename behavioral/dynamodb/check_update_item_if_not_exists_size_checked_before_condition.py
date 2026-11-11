"""update-item-if-not-exists-size-checked-before-condition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-if-not-exists-size-checked-before-condition"
GROUP = 'limits'
SERVICES = ['dynamodb']
_ERR_VALIDATION = ('ValidationException', 'Item size to update has exceeded the maximum allowed size')
_ERR_CONDITIONAL = ('ConditionalCheckFailedException', 'The conditional request failed')
_OVERSIZED_BYTES = 409700


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected success raises rather than returning a falsy pair.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _expect_error(fn, code: str, message: str) -> None:
    got = _code_and_message(fn)
    assert got == (code, message), f'expected {(code, message)!r}, got {got!r}'


def _run_scenarios(ddb, table: str) -> None:
    """Run the if_not_exists-size-vs-condition scenarios against one empty table."""
    # Positive control: a small if_not_exists update succeeds when its condition passes.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ctrl-pass'}, 'flag': {'BOOL': True}})
    ddb.update_item(
        TableName=table, Key={'pk': {'S': 'ctrl-pass'}},
        UpdateExpression='SET note = if_not_exists(note, :v)',
        ConditionExpression='flag = :true',
        ExpressionAttributeValues={':v': {'S': 'ok'}, ':true': {'BOOL': True}},
    )
    passed = ddb.get_item(TableName=table, Key={'pk': {'S': 'ctrl-pass'}}, ConsistentRead=True).get('Item', {})
    assert passed.get('note', {}).get('S') == 'ok', f'positive control note must round-trip, got {passed!r}'

    # Baseline: the same small update with a condition that genuinely fails raises
    # ConditionalCheckFailedException, proving the condition itself would fire here.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ctrl-fail'}, 'flag': {'BOOL': False}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'ctrl-fail'}},
        UpdateExpression='SET note = if_not_exists(note, :v)',
        ConditionExpression='flag = :true',
        ExpressionAttributeValues={':v': {'S': 'ok'}, ':true': {'BOOL': True}},
    ), *_ERR_CONDITIONAL)
    baseline = ddb.get_item(TableName=table, Key={'pk': {'S': 'ctrl-fail'}}, ConsistentRead=True).get('Item', {})
    assert 'note' not in baseline, f'a genuinely failed condition must leave no trace, got {baseline!r}'

    oversized = {'S': 'x' * _OVERSIZED_BYTES}

    # An oversized if_not_exists operand is refused for size whether its ConditionExpression
    # would pass...
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-pass'}, 'flag': {'BOOL': True}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'cond-pass'}},
        UpdateExpression='SET bigattr = if_not_exists(bigattr, :v)',
        ConditionExpression='flag = :true',
        ExpressionAttributeValues={':v': oversized, ':true': {'BOOL': True}},
    ), *_ERR_VALIDATION)
    after_pass = ddb.get_item(TableName=table, Key={'pk': {'S': 'cond-pass'}}, ConsistentRead=True).get('Item', {})
    assert 'bigattr' not in after_pass, f'a size refusal must leave no trace, got {after_pass!r}'

    # ...or would fail...
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-fail'}, 'flag': {'BOOL': False}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'cond-fail'}},
        UpdateExpression='SET bigattr = if_not_exists(bigattr, :v)',
        ConditionExpression='flag = :true',
        ExpressionAttributeValues={':v': oversized, ':true': {'BOOL': True}},
    ), *_ERR_VALIDATION)
    after_fail = ddb.get_item(TableName=table, Key={'pk': {'S': 'cond-fail'}}, ConsistentRead=True).get('Item', {})
    assert 'bigattr' not in after_fail, f'a size refusal must leave no trace, got {after_fail!r}'

    # ...or is absent entirely.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-absent'}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'cond-absent'}},
        UpdateExpression='SET bigattr = if_not_exists(bigattr, :v)',
        ExpressionAttributeValues={':v': oversized},
    ), *_ERR_VALIDATION)
    after_absent = ddb.get_item(TableName=table, Key={'pk': {'S': 'cond-absent'}}, ConsistentRead=True).get('Item', {})
    assert 'bigattr' not in after_absent, f'a size refusal must leave no trace, got {after_absent!r}'


def _create_table(ctx, ddb, table: str) -> None:
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem refuses an oversized if_not_exists operand for size before it evaluates
    ConditionExpression, in two Regions alike: never ConditionalCheckFailedException, whether
    the condition would pass, fail or is absent, and the stored item is left unchanged.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbsize-')
    _create_table(ctx, ddb, table)
    _run_scenarios(ddb, table)

    # region-pinned: the same size-before-condition order is asserted in us-east-1.
    ddb2 = ctx.client('dynamodb', region='us-east-1')
    table2 = ctx.unique_name('sim2real-behav-ddbsize-east-')
    _create_table(ctx, ddb2, table2)
    _run_scenarios(ddb2, table2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
