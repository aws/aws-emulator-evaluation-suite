"""atomic-counter-on-missing-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "atomic-counter-on-missing-attribute"
GROUP = 'atomic_counters'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD on a non-existent Number attribute initializes it to the increment value."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'new-counter'}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'new-counter'}}, UpdateExpression='ADD visits :inc', ExpressionAttributeValues={':inc': {'N': '1'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'new-counter'}}, ConsistentRead=True).get('Item')
    assert got['visits'] == {'N': '1'}, f"expected visits={{'N': '1'}} after ADD on missing attribute, got {got.get('visits')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
