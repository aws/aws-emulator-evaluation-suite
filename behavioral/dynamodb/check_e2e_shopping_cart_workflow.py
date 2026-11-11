"""e2e-shopping-cart-workflow."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-shopping-cart-workflow"
GROUP = 'e2e_workflows'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Shopping cart: BatchWrite items, Query, UpdateItem quantity, DeleteItem, verify."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'user_id', 'KeyType': 'HASH'}, {'AttributeName': 'item_id', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'user_id', 'AttributeType': 'S'}, {'AttributeName': 'item_id', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    items = [{'user_id': {'S': 'user-1'}, 'item_id': {'S': f'item-{i:03d}'}, 'quantity': {'N': '1'}, 'name': {'S': f'Product {i}'}} for i in range(5)]
    requests = [{'PutRequest': {'Item': item}} for item in items]
    ddb.batch_write_item(RequestItems={table: requests})
    resp = ddb.query(TableName=table, KeyConditionExpression='user_id = :uid', ExpressionAttributeValues={':uid': {'S': 'user-1'}}, ConsistentRead=True)
    assert resp['Count'] == 5, f"Expected 5 items, got {resp['Count']}"
    ddb.update_item(TableName=table, Key={'user_id': {'S': 'user-1'}, 'item_id': {'S': 'item-002'}}, UpdateExpression='SET quantity = :q', ExpressionAttributeValues={':q': {'N': '3'}})
    ddb.delete_item(TableName=table, Key={'user_id': {'S': 'user-1'}, 'item_id': {'S': 'item-004'}})
    resp2 = ddb.query(TableName=table, KeyConditionExpression='user_id = :uid', ExpressionAttributeValues={':uid': {'S': 'user-1'}}, ConsistentRead=True)
    assert resp2['Count'] == 4, f"Expected 4 items after delete, got {resp2['Count']}"
    updated = ddb.get_item(TableName=table, Key={'user_id': {'S': 'user-1'}, 'item_id': {'S': 'item-002'}}, ConsistentRead=True).get('Item')
    assert updated['quantity'] == {'N': '3'}, f"Expected quantity 3, got {updated['quantity']}"
    deleted = ddb.get_item(TableName=table, Key={'user_id': {'S': 'user-1'}, 'item_id': {'S': 'item-004'}}, ConsistentRead=True).get('Item')
    assert deleted is None, 'item-004 should be deleted'
    try:
        ddb.update_item(TableName=table, Key={'user_id': {'S': 'user-1'}, 'item_id': {'S': 'item-004'}}, UpdateExpression='SET quantity = :q', ConditionExpression='attribute_exists(item_id)', ExpressionAttributeValues={':q': {'N': '9'}})
    except ClientError as exc:
        code = exc.response['Error']['Code']
        assert code == 'ConditionalCheckFailedException', f"Expected ConditionalCheckFailedException updating deleted item-004, got {code}"
        message = exc.response['Error'].get('Message')
        assert message == 'The conditional request failed', f"Expected the conditional-check message, got {message!r}"
    else:
        raise AssertionError('Expected ConditionalCheckFailedException updating deleted item-004, call succeeded')

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
