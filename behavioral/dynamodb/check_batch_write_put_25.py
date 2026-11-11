"""batch-write-put-25."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-write-put-25"
GROUP = 'batch'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem accepts up to 25 put requests in one call and persists all of them."""
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
    requests = [{'PutRequest': {'Item': {'pk': {'S': f'bw-{i:03d}'}, 'data': {'S': 'x'}}}} for i in range(25)]
    resp = ddb.batch_write_item(RequestItems={table: requests})
    unprocessed = resp.get('UnprocessedItems', {}).get(table, [])
    assert not unprocessed, f"expected all 25 puts accepted, got {len(unprocessed)} unprocessed: {unprocessed!r}"
    scan = ddb.scan(TableName=table, ConsistentRead=True, Select='COUNT')
    assert scan['Count'] == 25, f"expected 25 items persisted, found {scan['Count']}"
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'bw-000'}}, ConsistentRead=True).get('Item')
    assert got is not None, "expected item bw-000 to be retrievable after batch write"
    assert got['data']['S'] == 'x', f"expected data attribute 'x', got {got.get('data')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
