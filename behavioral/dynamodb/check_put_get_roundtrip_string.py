"""put-get-roundtrip-string."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-roundtrip-string"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem/GetItem round-trips a string attribute exactly."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'}, {'Key': 'sim2real:prefix', 'Value': 'sim2real-behav'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    item = {'pk': {'S': 'test-1'}, 'data': {'S': 'hello world'}}
    ddb.put_item(TableName=table, Item=item)
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'test-1'}}, ConsistentRead=True).get('Item')
    assert got == item, f'expected {item!r}, got {got!r}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
