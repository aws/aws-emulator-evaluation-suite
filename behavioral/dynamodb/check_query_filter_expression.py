"""query-filter-expression."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-expression"
GROUP = 'query'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterExpression is applied after the key-condition read: ScannedCount reflects the
    pre-filter items examined, Count reflects the post-filter items actually returned."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(5):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'f'}, 'sk': {'S': f'{i:03d}'}, 'status': {'S': 'active' if i % 2 == 0 else 'inactive'}})
    resp = ddb.query(TableName=table, KeyConditionExpression='pk = :pk', FilterExpression='#st = :s', ExpressionAttributeNames={'#st': 'status'}, ExpressionAttributeValues={':pk': {'S': 'f'}, ':s': {'S': 'active'}}, ConsistentRead=True)
    assert resp['Count'] == 3, f"Count must reflect the 3 post-filter 'active' items, got {resp['Count']} Items={resp.get('Items')}"
    assert resp['ScannedCount'] == 5, f"ScannedCount must reflect all 5 pre-filter items examined under the key condition, got {resp['ScannedCount']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
