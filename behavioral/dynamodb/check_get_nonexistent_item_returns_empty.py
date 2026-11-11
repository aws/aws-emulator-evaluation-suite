"""get-nonexistent-item-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-nonexistent-item-returns-empty"
GROUP = 'item_crud'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem for a non-existent key returns empty (no Item key), not an error."""
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
    resp = ddb.get_item(TableName=table, Key={'pk': {'S': 'ghost'}}, ConsistentRead=True)
    assert 'Item' not in resp, f"expected no Item for a key never written, got {resp.get('Item')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
