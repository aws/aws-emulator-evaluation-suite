"""atomic-increment."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "atomic-increment"
GROUP = 'atomic_counters'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD on Number attribute performs atomic increment correctly."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real-check', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'counter'}, 'hits': {'N': '0'}})
    for _ in range(5):
        ddb.update_item(TableName=table, Key={'pk': {'S': 'counter'}}, UpdateExpression='ADD hits :inc', ExpressionAttributeValues={':inc': {'N': '1'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'counter'}}, ConsistentRead=True).get('Item')
    assert got is not None, 'counter item vanished after 5 ADD increments'
    assert got['hits'] == {'N': '5'}, f"expected hits=5 after five +1 ADD updates, got {got.get('hits')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
