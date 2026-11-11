"""scan-pagination-exclusive-start-key."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "scan-pagination-exclusive-start-key"
GROUP = 'pagination'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan pagination with ExclusiveStartKey honors Limit and yields every item exactly once."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    expected_pks = {f'sp-{i:03d}' for i in range(12)}
    for pk in expected_pks:
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}})
    all_items: list[dict] = []
    page_count = 0
    params: dict[str, Any] = {'TableName': table, 'Limit': 4, 'ConsistentRead': True}
    while True:
        resp = ddb.scan(**params)
        page_count += 1
        assert len(resp['Items']) <= 4, f'page {page_count} returned {len(resp["Items"])} items, exceeding Limit=4'
        all_items.extend(resp['Items'])
        if 'LastEvaluatedKey' not in resp:
            break
        params['ExclusiveStartKey'] = resp['LastEvaluatedKey']
    assert page_count > 1, f'expected pagination across multiple pages for 12 items under Limit=4, got {page_count} page(s)'
    assert len(all_items) == 12, f'expected 12 total items across all pages, got {len(all_items)}'
    pks = {item['pk']['S'] for item in all_items}
    assert pks == expected_pks, f'expected pks {sorted(expected_pks)}, got {sorted(pks)}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
