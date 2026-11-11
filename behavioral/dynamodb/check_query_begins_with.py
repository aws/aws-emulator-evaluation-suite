"""query-begins-with."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-begins-with"
GROUP = 'query'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with begins_with on sort key filters correctly."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'p'}, 'sk': {'S': 'order#001'}, 't': {'S': 'a'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'p'}, 'sk': {'S': 'order#002'}, 't': {'S': 'b'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'p'}, 'sk': {'S': 'profile#1'}, 't': {'S': 'c'}})
    resp = ddb.query(TableName=table, KeyConditionExpression='pk = :pk AND begins_with(sk, :prefix)', ExpressionAttributeValues={':pk': {'S': 'p'}, ':prefix': {'S': 'order#'}}, ConsistentRead=True)
    assert resp['Count'] == 2, f"expected 2 items matching begins_with(sk, 'order#'), got Count={resp['Count']} Items={resp['Items']}"
    assert all((item['sk']['S'].startswith('order#') for item in resp['Items'])), f"expected every returned item's sk to start with 'order#', got {[item['sk']['S'] for item in resp['Items']]}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
