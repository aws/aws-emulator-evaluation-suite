"""update-expression-add-number."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-expression-add-number"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression ADD on a Number attribute performs atomic increment."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'upd-add'}, 'hits': {'N': '10'}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'upd-add'}}, UpdateExpression='ADD hits :inc', ExpressionAttributeValues={':inc': {'N': '5'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'upd-add'}}, ConsistentRead=True).get('Item')
    assert got['hits'] == {'N': '15'}, f"expected ADD hits :inc(5) on hits=10 to yield hits=15, got {got}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
