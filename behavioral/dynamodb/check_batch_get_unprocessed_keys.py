"""batch-get-unprocessed-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-unprocessed-keys"
GROUP = 'batch'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetItem with a key for a nonexistent item omits it from Responses without error and never lists
    it in UnprocessedKeys: a missing item is not a deferred key."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': 'batch-get-unprocessed-keys'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'exists-1'}, 'v': {'S': 'yes'}})
    resp = ddb.batch_get_item(RequestItems={table: {'Keys': [{'pk': {'S': 'exists-1'}}, {'pk': {'S': 'ghost-1'}}], 'ConsistentRead': True}})
    items = resp['Responses'][table]
    assert len(items) == 1, f'expected exactly 1 existing item back, got {len(items)!r}: {items!r}'
    assert items[0]['pk']['S'] == 'exists-1', f'expected pk exists-1, got {items[0]["pk"]!r}'
    unprocessed = resp.get('UnprocessedKeys', {})
    assert unprocessed == {}, (
        f'a key for a non-existent item was reported as unprocessed instead of simply absent: '
        f'{unprocessed!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
