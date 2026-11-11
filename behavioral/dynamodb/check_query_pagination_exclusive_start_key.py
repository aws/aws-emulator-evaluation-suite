"""query-pagination-exclusive-start-key."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "query-pagination-exclusive-start-key"
GROUP = 'pagination'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query pagination with ExclusiveStartKey yields all items across pages."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'true'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(10):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'pag'}, 'sk': {'S': f'{i:03d}'}})
    all_items: list[dict] = []
    pages = 0
    params: dict[str, Any] = {'TableName': table, 'KeyConditionExpression': 'pk = :pk', 'ExpressionAttributeValues': {':pk': {'S': 'pag'}}, 'Limit': 3, 'ConsistentRead': True}
    while True:
        resp = ddb.query(**params)
        pages += 1
        all_items.extend(resp['Items'])
        if 'LastEvaluatedKey' not in resp:
            break
        params['ExclusiveStartKey'] = resp['LastEvaluatedKey']
    # 10 items at Limit=3 is ceil(10/3) = 4 pages; fewer means Limit/ExclusiveStartKey was
    # not actually honoured and the whole result came back in one shot.
    assert pages == 4, f'expected 4 pages of Limit=3 over 10 items, got {pages} pages -- Limit was not honoured'
    sks = [item['sk']['S'] for item in all_items]
    assert len(sks) == 10, f'expected 10 items reassembled across pages, got {len(sks)}: {sks!r}'
    assert len(set(sks)) == 10, f'pagination returned a duplicate sort key across pages: {sks!r}'
    assert sks == sorted(sks), f'expected sort keys in ascending order, got {sks!r}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
