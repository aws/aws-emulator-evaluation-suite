"""condition-attribute-type-gates-the-write."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "condition-attribute-type-gates-the-write"
GROUP = 'conditions'
SERVICES = ['dynamodb']


def _error(call, what):
    """The Error dict from a call that MUST be refused."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """attribute_type in a ConditionExpression compares the STORED type, so a write conditioned on the
    wrong type is refused and the item is left as it was."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'v': {'N': '1'}})
    err = _error(
        lambda: ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'v': {'N': '2'}},
                             ConditionExpression='attribute_type(v, :t)',
                             ExpressionAttributeValues={':t': {'S': 'S'}}),
        'a write conditioned on v being a String when it is a Number',
    )
    assert err.get('Code') == 'ConditionalCheckFailedException', (
        f"expected ConditionalCheckFailedException, got {err.get('Code')}"
    )
    assert err.get('Message') == 'The conditional request failed', (
        f"expected 'The conditional request failed', got {err.get('Message')!r}"
    )
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}}, ConsistentRead=True)['Item']
    assert got['v'] == {'N': '1'}, f'the refused write must leave v at 1, got {got}'
    # The same condition with the RIGHT type succeeds, so the refusal above was the type and not
    # the function being unimplemented.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'v': {'N': '3'}},
                 ConditionExpression='attribute_type(v, :t)',
                 ExpressionAttributeValues={':t': {'S': 'N'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}}, ConsistentRead=True)['Item']
    assert got['v'] == {'N': '3'}, f'the matching condition must let the write through, got {got}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
