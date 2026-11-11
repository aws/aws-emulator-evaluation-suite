"""error-conditional-check-failed-shape."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-conditional-check-failed-shape"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConditionalCheckFailedException includes the correct error shape, and a rejected
    conditional PutItem leaves the pre-existing item untouched until the condition is
    actually met again."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: the same condition succeeds while the item does not yet exist,
    # proving the condition is actually evaluated rather than always rejected.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'shape-test'}, 'v': {'N': '1'}}, ConditionExpression='attribute_not_exists(pk)')

    # Break exactly one thing: the identical condition is now false because the item exists.
    try:
        ddb.put_item(TableName=table, Item={'pk': {'S': 'shape-test'}, 'v': {'N': '2'}}, ConditionExpression='attribute_not_exists(pk)')
        err_resp = None
    except ClientError as exc:
        err_resp = exc.response
    assert err_resp is not None, "expected ConditionalCheckFailedException, got a successful PutItem"
    error = err_resp['Error']
    assert error['Code'] == ERR_CONDITIONAL_CHECK_FAILED, f"expected {ERR_CONDITIONAL_CHECK_FAILED}, got {error.get('Code')}"
    assert error['Message'] == "The conditional request failed", (
        f"expected the exact ConditionalCheckFailedException message AWS returns, got {error['Message']!r}"
    )
    message = error.get('Message') or error.get('message')
    assert message, f"expected a non-empty Message on {ERR_CONDITIONAL_CHECK_FAILED}, got {error}"

    # Effect absent: an independent read shows the rejected write never landed.
    after_reject = ddb.get_item(TableName=table, Key={'pk': {'S': 'shape-test'}}, ConsistentRead=True)
    assert after_reject.get('Item', {}).get('v') == {'N': '1'}, f"expected v=1 to survive the rejected write, got {after_reject.get('Item')}"

    # Restore: delete the item, prove it is gone, then the identical condition succeeds again.
    ddb.delete_item(TableName=table, Key={'pk': {'S': 'shape-test'}})
    after_delete = ddb.get_item(TableName=table, Key={'pk': {'S': 'shape-test'}}, ConsistentRead=True)
    assert 'Item' not in after_delete, f"expected shape-test to be gone after delete, got {after_delete.get('Item')}"

    ddb.put_item(TableName=table, Item={'pk': {'S': 'shape-test'}, 'v': {'N': '3'}}, ConditionExpression='attribute_not_exists(pk)')
    after_restore = ddb.get_item(TableName=table, Key={'pk': {'S': 'shape-test'}}, ConsistentRead=True)
    assert after_restore.get('Item', {}).get('v') == {'N': '3'}, f"expected v=3 after the restored write succeeded, got {after_restore.get('Item')}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
