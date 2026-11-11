"""put-return-values-all-old."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-return-values-all-old"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem with ReturnValues=ALL_OLD returns the previous item."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    key = {'pk': {'S': 'rv-test'}}
    ddb.put_item(TableName=table, Item={**key, 'v': {'N': '1'}})
    resp = ddb.put_item(TableName=table, Item={**key, 'v': {'N': '2'}}, ReturnValues='ALL_OLD')
    old = resp.get('Attributes')
    assert old is not None, f'PutItem with ReturnValues=ALL_OLD must return Attributes, got {resp}'
    assert old == {'pk': {'S': 'rv-test'}, 'v': {'N': '1'}}, (
        f'ALL_OLD must return the complete prior item including the key, got {old}'
    )

    current = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert current == {'pk': {'S': 'rv-test'}, 'v': {'N': '2'}}, (
        f'independent read after the overwrite must show the new item, got {current}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
