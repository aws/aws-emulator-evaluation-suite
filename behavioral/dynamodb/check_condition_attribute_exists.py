"""condition-attribute-exists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-attribute-exists"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConditionExpression attribute_exists succeeds when the attribute is present, and
    is actually enforced (not a no-op) once that attribute is removed."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- Positive control: flag is present, so attribute_exists(flag) must let the write through.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-1'}, 'flag': {'S': 'active'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-1'}, 'flag': {'S': 'updated'}}, ConditionExpression='attribute_exists(flag)')
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'cond-1'}}, ConsistentRead=True).get('Item')
    assert got is not None and got.get('flag') == {'S': 'updated'}, (
        f"positive control: expected flag=updated after a satisfied attribute_exists condition, got {got!r}"
    )

    # --- Break exactly one thing: overwrite the item so it no longer carries `flag`.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-1'}})

    # --- The identical condition must now be refused with the specific error.
    try:
        ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-1'}, 'flag': {'S': 'should-not-apply'}}, ConditionExpression='attribute_exists(flag)')
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_CONDITIONAL_CHECK_FAILED, (
        f"expected {ERR_CONDITIONAL_CHECK_FAILED} once flag is absent, got {code!r}"
    )
    assert message == "The conditional request failed", (
        f"expected AWS's exact ConditionalCheckFailedException message, got {message!r}"
    )

    # --- Effect absent: the rejected write must not have applied.
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'cond-1'}}, ConsistentRead=True).get('Item')
    assert got is not None and 'flag' not in got, f"rejected conditional put must not apply; got item {got!r}"

    # --- Restore, then the identical call must succeed again.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-1'}, 'flag': {'S': 'active'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cond-1'}, 'flag': {'S': 'updated'}}, ConditionExpression='attribute_exists(flag)')
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'cond-1'}}, ConsistentRead=True).get('Item')
    assert got is not None and got.get('flag') == {'S': 'updated'}, (
        f"expected flag=updated after restoring flag and re-applying the same condition, got {got!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
