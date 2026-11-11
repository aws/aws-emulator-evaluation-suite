"""query-scan-index-forward-false."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-scan-index-forward-false"
GROUP = 'query'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with ScanIndexForward=False returns items in descending sort key order."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(5):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'u'}, 'sk': {'S': f'{i:03d}'}})
    resp = ddb.query(TableName=table, KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'u'}}, ScanIndexForward=False, ConsistentRead=True)
    sks = [item['sk']['S'] for item in resp['Items']]
    expected = [f'{i:03d}' for i in range(4, -1, -1)]
    assert sks == expected, f'ScanIndexForward=False must return all 5 items in descending sk order {expected}, got {sks}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
