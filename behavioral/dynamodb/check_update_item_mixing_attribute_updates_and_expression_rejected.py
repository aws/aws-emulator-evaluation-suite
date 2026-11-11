"""update-item-mixing-attribute-updates-and-expression-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-mixing-attribute-updates-and-expression-rejected"
GROUP = 'legacy'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AttributeUpdates and UpdateExpression are mutually exclusive, and the refusal names the
    non-expression parameter."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error_code(
        lambda: ddb.update_item(TableName=table, Key={'pk': {'S': 'a'}},
                                UpdateExpression='SET x = :v',
                                ExpressionAttributeValues={':v': {'S': '1'}},
                                AttributeUpdates={'y': {'Value': {'S': '2'}, 'Action': 'PUT'}}),
        'an UpdateItem sending both AttributeUpdates and UpdateExpression',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = ('1 validation error detected: Can not use both expression and non-expression parameters in '
                'the same request: Non-expression parameters: {AttributeUpdates} Expression parameters: '
                '{UpdateExpression}')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert 'Item' not in ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}}, ConsistentRead=True), (
        'the refused update must not create the item'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
