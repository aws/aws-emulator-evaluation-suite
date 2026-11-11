"""condition-attribute-not-exists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-attribute-not-exists"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConditionExpression attribute_not_exists succeeds while the attribute is absent,
    fails once it is present, and succeeds again once it is removed — proving the
    condition tracks live state rather than always accepting or always rejecting."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {'pk': {'S': 'cond-2'}}

    # Positive control: item exists but has no 'flag' attribute yet, so the
    # condition must be satisfied and the put must succeed.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-2'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-2'}, 'flag': {'S': 'active'}}, ConditionExpression='attribute_not_exists(flag)')
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert got is not None and got.get('flag') == {'S': 'active'}, f"positive control: expected flag=active after unconditional-attribute-absent put, got {got}"

    # Break: 'flag' is now present, so the identical condition must reject the next write.
    try:
        ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-2'}, 'flag': {'S': 'changed'}}, ConditionExpression='attribute_not_exists(flag)')
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_CONDITIONAL_CHECK_FAILED, f"expected {ERR_CONDITIONAL_CHECK_FAILED}, got {code}"
    assert message == "The conditional request failed", (
        f"expected AWS's exact ConditionalCheckFailedException message, got {message!r}"
    )

    # Effect absent: an independent read shows the rejected write never landed.
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert got is not None and got.get('flag') == {'S': 'active'}, f"rejected put must not change state, got {got}"

    # Restore: remove 'flag' so the condition is satisfiable again.
    ddb.update_item(TableName=table, Key=key, UpdateExpression='REMOVE flag')

    # The identical call now succeeds against the restored state.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-2'}, 'flag': {'S': 'changed'}}, ConditionExpression='attribute_not_exists(flag)')
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert got is not None and got.get('flag') == {'S': 'changed'}, f"expected flag=changed after restored attribute-absent put, got {got}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
