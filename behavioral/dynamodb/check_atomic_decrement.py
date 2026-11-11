"""atomic-decrement."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "atomic-decrement"
GROUP = 'atomic_counters'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD with negative Number performs atomic decrement."""
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
    ddb.put_item(TableName=table, Item={'pk': {'S': 'dec'}, 'balance': {'N': '100'}})
    ddb.update_item(TableName=table, Key={'pk': {'S': 'dec'}}, UpdateExpression='ADD balance :dec', ExpressionAttributeValues={':dec': {'N': '-30'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'dec'}}, ConsistentRead=True).get('Item')
    assert got['balance'] == {'N': '70'}, f"expected balance {{'N': '70'}} after ADD -30, got {got.get('balance')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
