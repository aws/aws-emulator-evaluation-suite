"""scan-with-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-with-filter"
GROUP = 'scan'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan with FilterExpression returns only matching items."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(6):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'sf-{i}'}, 'even': {'BOOL': i % 2 == 0}})
    resp = ddb.scan(TableName=table, FilterExpression='even = :t', ExpressionAttributeValues={':t': {'BOOL': True}}, ConsistentRead=True)
    assert resp['ScannedCount'] == 6, f"expected Scan to examine all 6 items before filtering, got ScannedCount={resp['ScannedCount']}"
    assert resp['Count'] == 3, f"expected 3 items matching even=True, got Count={resp['Count']}"
    returned_pks = {item['pk']['S'] for item in resp['Items']}
    assert returned_pks == {'sf-0', 'sf-2', 'sf-4'}, f"expected only even-indexed items, got {sorted(returned_pks)}"
    assert all(item['even']['BOOL'] is True for item in resp['Items']), f"a returned item had even != True: {resp['Items']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
