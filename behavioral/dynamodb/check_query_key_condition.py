"""query-key-condition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-key-condition"
GROUP = 'query'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with a KeyConditionExpression returns exactly the five items of its partition in ascending sort-key order,
    although they are written out of order and beside another partition.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    expected_sks = ['item-000', 'item-001', 'item-002', 'item-003', 'item-004']
    for sk in ['item-003', 'item-000', 'item-004', 'item-001', 'item-002']:
        ddb.put_item(TableName=table, Item={'pk': {'S': 'user-1'}, 'sk': {'S': sk}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'user-2'}, 'sk': {'S': 'item-000'}})
    resp = ddb.query(TableName=table, KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'user-1'}}, ConsistentRead=True)
    assert resp['Count'] == 5, f'expected 5 items for user-1, got {resp["Count"]!r}'
    sks = [item['sk']['S'] for item in resp['Items']]
    assert sks == expected_sks, f'expected SK-ascending order {expected_sks!r}, got {sks!r}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
