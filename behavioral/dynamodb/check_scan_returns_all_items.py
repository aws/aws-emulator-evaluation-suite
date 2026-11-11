"""scan-returns-all-items."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "scan-returns-all-items"
GROUP = 'scan'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full table scan returns every item that was written, unaltered."""
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
    expected = {f'scan-{i}': i for i in range(7)}
    for pk, x in expected.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'x': {'N': str(x)}})
    items = []
    params: dict[str, Any] = {'TableName': table, 'ConsistentRead': True}
    while True:
        resp = ddb.scan(**params)
        items.extend(resp['Items'])
        if 'LastEvaluatedKey' not in resp:
            break
        params['ExclusiveStartKey'] = resp['LastEvaluatedKey']
    assert len(items) == len(expected), f"expected {len(expected)} items, scan returned {len(items)}"
    seen = {item['pk']['S']: int(item['x']['N']) for item in items}
    assert seen == expected, f"scan item mismatch: expected {expected}, got {seen}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
