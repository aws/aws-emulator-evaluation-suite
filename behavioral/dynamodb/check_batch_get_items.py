"""batch-get-items."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-items"
GROUP = 'batch'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetItem retrieves multiple items by key in one call."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(5):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'bg-{i}'}, 'val': {'N': str(i)}})
    resp = ddb.batch_get_item(RequestItems={table: {'Keys': [{'pk': {'S': f'bg-{i}'}} for i in range(5)], 'ConsistentRead': True}})
    unprocessed = resp.get('UnprocessedKeys', {})
    assert unprocessed == {}, f"expected no unprocessed keys for a 5-key request, got {unprocessed}"
    items = resp['Responses'][table]
    assert len(items) == 5, f"expected 5 items, got {len(items)}: {items}"
    values = {item['pk']['S']: item['val']['N'] for item in items}
    assert values == {f'bg-{i}': str(i) for i in range(5)}, f"expected exact pk->val mapping, got {values}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
