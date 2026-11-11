"""condition-on-missing-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-on-missing-item"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConditionExpression on a non-existent item raises ConditionalCheckFailedException; the same expression succeeds once the item exists."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: attribute_exists(pk) succeeds against an item that is already there.
    control_key = 'has-item'
    ddb.put_item(TableName=table, Item={'pk': {'S': control_key}, 'v': {'S': 'seed'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': control_key}, 'v': {'S': 'seed2'}}, ConditionExpression='attribute_exists(pk)')
    control_got = ddb.get_item(TableName=table, Key={'pk': {'S': control_key}}, ConsistentRead=True).get('Item')
    assert control_got == {'pk': {'S': control_key}, 'v': {'S': 'seed2'}}, f"positive control: expected the conditional put to land, got {control_got!r}"

    # Break exactly one thing: the same condition against a pk that was never created.
    target_key = 'no-such-item'
    try:
        ddb.put_item(TableName=table, Item={'pk': {'S': target_key}, 'v': {'S': 'x'}}, ConditionExpression='attribute_exists(pk)')
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_CONDITIONAL_CHECK_FAILED, f"expected {ERR_CONDITIONAL_CHECK_FAILED}, got {code!r}"
    assert message == "The conditional request failed", (
        f"expected AWS's exact ConditionalCheckFailedException message, got {message!r}"
    )

    # Effect absent: the rejected put created nothing.
    absent = ddb.get_item(TableName=table, Key={'pk': {'S': target_key}}, ConsistentRead=True).get('Item')
    assert absent is None, f"expected no item at {target_key!r} after the rejected put, got {absent!r}"

    # Restore: create the item, then the identical call now succeeds.
    ddb.put_item(TableName=table, Item={'pk': {'S': target_key}, 'v': {'S': 'seed'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': target_key}, 'v': {'S': 'x'}}, ConditionExpression='attribute_exists(pk)')
    restored = ddb.get_item(TableName=table, Key={'pk': {'S': target_key}}, ConsistentRead=True).get('Item')
    assert restored == {'pk': {'S': target_key}, 'v': {'S': 'x'}}, f"expected the restored conditional put to land, got {restored!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
