"""transact-write-items-duplicate-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-duplicate-key-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """Two actions on the same item in one transaction are refused, with a message naming the
    multiple-operations rule rather than a generic parse error."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error_code(
        lambda: ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'dup'}}}},
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'dup'}}}}]),
        'a transaction with two actions on one item',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = 'Transaction request cannot include multiple operations on one item'
    assert err.get('Message') == expected, f'expected message {expected!r}, got {err.get("Message")!r}'
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, 'nothing may be written'

    # An ExpressionAttributeValues entry unused by the second action is rejected on its own terms,
    # ahead of any multiple-operations check, and nothing from either action is written.
    err2 = _error_code(
        lambda: ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'a'}}}},
            {'Put': {
                'TableName': table, 'Item': {'pk': {'S': 'b'}},
                'ConditionExpression': 'attribute_not_exists(pk)',
                'ExpressionAttributeValues': {':unused': {'S': 'x'}},
            }},
        ]),
        'a transaction whose second action declares an unused ExpressionAttributeValues entry',
    )
    assert err2.get('Code') == 'ValidationException', f"expected ValidationException, got {err2.get('Code')}"
    expected2 = 'Value provided in ExpressionAttributeValues unused in expressions: keys: {:unused}'
    assert err2.get('Message') == expected2, f'expected message {expected2!r}, got {err2.get("Message")!r}'
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, 'nothing may be written'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
