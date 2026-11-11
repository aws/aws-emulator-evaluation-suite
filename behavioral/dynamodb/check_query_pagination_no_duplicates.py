"""query-pagination-no-duplicates."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "query-pagination-no-duplicates"
GROUP = 'pagination'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginated query never returns duplicate items."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(15):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'nodup'}, 'sk': {'S': f'{i:04d}'}})
    seen_sks: list[str] = []
    pages = 0
    params: dict[str, Any] = {'TableName': table, 'KeyConditionExpression': 'pk = :pk', 'ExpressionAttributeValues': {':pk': {'S': 'nodup'}}, 'Limit': 4, 'ConsistentRead': True}
    while True:
        resp = ddb.query(**params)
        pages += 1
        for item in resp['Items']:
            sk = item['sk']['S']
            assert sk not in seen_sks, f'Duplicate item: {sk}'
            seen_sks.append(sk)
        if 'LastEvaluatedKey' not in resp:
            break
        params['ExclusiveStartKey'] = resp['LastEvaluatedKey']
    # 15 items at Limit=4 is at least 4 pages; fewer means the service ignored Limit and the
    # dedup logic above was never exercised across a real page boundary.
    assert pages >= 4, f'expected at least 4 pages for 15 items at Limit=4, got {pages}'
    assert len(seen_sks) == 15, f'expected 15 unique items across all pages, got {len(seen_sks)}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
