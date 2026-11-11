"""e2e-paginated-export."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "e2e-paginated-export"
GROUP = 'e2e_workflows'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginated scan: write 30 items, scan with Limit=10, collect all pages, no duplicates."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for batch_start in range(0, 30, 25):
        batch_end = min(batch_start + 25, 30)
        requests = [{'PutRequest': {'Item': {'pk': {'S': f'export-{i:03d}'}, 'seq': {'N': str(i)}}}} for i in range(batch_start, batch_end)]
        ddb.batch_write_item(RequestItems={table: requests})
    all_items: list[dict] = []
    params: dict[str, Any] = {'TableName': table, 'Limit': 10, 'ConsistentRead': True}
    pages = 0
    while True:
        resp = ddb.scan(**params)
        assert len(resp['Items']) <= 10, f"Page had {len(resp['Items'])} items, Limit=10 was not honoured"
        all_items.extend(resp['Items'])
        pages += 1
        if 'LastEvaluatedKey' not in resp:
            break
        params['ExclusiveStartKey'] = resp['LastEvaluatedKey']
    assert pages >= 3, (
        f'30 items at Limit=10 requires at least 3 pages, got {pages} -- the service ignored Limit'
    )
    pks = [item['pk']['S'] for item in all_items]
    assert len(pks) == 30, f'Expected 30 items, got {len(pks)}'
    assert len(set(pks)) == 30, f'Duplicate items found: {len(pks)} total, {len(set(pks))} unique'
    expected = {f'export-{i:03d}' for i in range(30)}
    assert set(pks) == expected, f'Expected pks {sorted(expected)}, got {sorted(set(pks))}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
