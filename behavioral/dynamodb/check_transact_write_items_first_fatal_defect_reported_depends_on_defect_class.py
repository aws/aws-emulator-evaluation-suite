"""transact-write-items-first-fatal-defect-reported-depends-on-defect-class."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-first-fatal-defect-reported-depends-on-defect-class"
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _error(call, what):
    try:
        result = call()
    except ClientError as exc:
        return exc.response['Error']
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it: {result!r}')


def _wait_table_active(ctx, ddb, table):
    """Poll DescribeTable to ACTIVE, bounded by the run's remaining time."""
    deadline = time.monotonic() + max(1.0, min(60.0, (ctx.time_left() or 60.0) - 10.0))
    status = ddb.describe_table(TableName=table)['Table']['TableStatus']
    while status != 'ACTIVE' and time.monotonic() < deadline:
        time.sleep(2)
        status = ddb.describe_table(TableName=table)['Table']['TableStatus']
    assert status == 'ACTIVE', f"table did not reach ACTIVE in time, last status {status!r}"


def _nested_string(depth):
    """A map nested ``depth`` levels deep, past DynamoDB's 32-level document limit."""
    value = {'S': 'leaf'}
    for _ in range(depth - 1):
        value = {'M': {'n': value}}
    return value


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """Across two actions each carrying one defect, an unused ExpressionAttributeValues key beats
    a missing table regardless of which action lists it first, while a malformed condition
    expression and a 33-level-deep item are each reported only when listed first."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    missing_table = ctx.unique_name('sim2real-behav-missing-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_active(ctx, ddb, table)
    ddb.put_item(TableName=table, Item={'pk': {'S': 'existing'}, 'v': {'N': '1'}})

    # Positive control: a well-formed transaction is accepted.
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'control'}}}}])
    assert ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True).get('Item'), (
        'the positive control item must exist after a well-formed TransactWriteItems'
    )

    unused_value_action = {'Update': {
        'TableName': table,
        'Key': {'pk': {'S': 'existing'}},
        'UpdateExpression': 'SET v = v + :inc',
        'ExpressionAttributeValues': {':inc': {'N': '1'}, ':unused': {'N': '99'}},
    }}
    missing_table_action = {'Put': {'TableName': missing_table, 'Item': {'pk': {'S': 'x'}}}}
    unused_value_message = 'Value provided in ExpressionAttributeValues unused in expressions: keys: {:unused}'

    err_a1 = _error(
        lambda: ddb.transact_write_items(TransactItems=[missing_table_action, unused_value_action]),
        'missing table first, unused expression value second',
    )
    assert err_a1['Code'] == 'ValidationException', f"expected ValidationException, got {err_a1['Code']!r}"
    assert err_a1['Message'] == unused_value_message, f"expected {unused_value_message!r}, got {err_a1['Message']!r}"

    err_a2 = _error(
        lambda: ddb.transact_write_items(TransactItems=[unused_value_action, missing_table_action]),
        'unused expression value first, missing table second',
    )
    assert err_a2['Code'] == 'ValidationException', f"expected ValidationException, got {err_a2['Code']!r}"
    assert err_a2['Message'] == unused_value_message, f"expected {unused_value_message!r}, got {err_a2['Message']!r}"

    malformed_condition_action = {'ConditionCheck': {
        'TableName': table,
        'Key': {'pk': {'S': 'cc-key'}},
        'ConditionExpression': 'attribute_exists(pk AND',
    }}
    deep_item_action = {'Put': {'TableName': table, 'Item': {'pk': {'S': 'deep33'}, 'blob': _nested_string(33)}}}
    condition_syntax_message = 'Invalid ConditionExpression: Syntax error; token: "AND", near: "pk AND"'
    nesting_message = ('Nesting Levels have exceeded supported limits: Attributes in the item have '
                       'nested levels beyond supported limit')

    err_b1 = _error(
        lambda: ddb.transact_write_items(TransactItems=[malformed_condition_action, deep_item_action]),
        'malformed condition first, 33-level item second',
    )
    assert err_b1['Code'] == 'ValidationException', f"expected ValidationException, got {err_b1['Code']!r}"
    assert err_b1['Message'] == condition_syntax_message, (
        f"listing the malformed condition first must report it; expected {condition_syntax_message!r}, "
        f"got {err_b1['Message']!r}"
    )

    err_b2 = _error(
        lambda: ddb.transact_write_items(TransactItems=[deep_item_action, malformed_condition_action]),
        '33-level item first, malformed condition second',
    )
    assert err_b2['Code'] == 'ValidationException', f"expected ValidationException, got {err_b2['Code']!r}"
    assert err_b2['Message'] == nesting_message, (
        f"listing the 33-level item first must report it; expected {nesting_message!r}, "
        f"got {err_b2['Message']!r}"
    )

    remaining = ddb.get_item(TableName=table, Key={'pk': {'S': 'existing'}}, ConsistentRead=True)['Item']
    assert remaining['v'] == {'N': '1'}, (
        f"none of the four rejected transactions may touch the existing item; v is {remaining['v']!r}"
    )
    items = {i['pk']['S'] for i in ddb.scan(TableName=table, ConsistentRead=True)['Items']}
    assert items == {'control', 'existing'}, (
        f"none of the four rejected transactions may write anything; table holds {sorted(items)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
