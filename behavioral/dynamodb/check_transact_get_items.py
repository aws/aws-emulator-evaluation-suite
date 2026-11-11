"""transact-get-items."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items"
GROUP = 'transactions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems retrieves multiple items atomically, and -- because it performs a
    two-phase strongly-consistent read to guard against a concurrent write -- consumes exactly
    twice the read capacity of the equivalent standalone GetItem calls on the same items."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'tg-1'}, 'v': {'N': '10'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'tg-2'}, 'v': {'N': '20'}})

    baseline_capacity = 0.0
    for key in ('tg-1', 'tg-2'):
        single = ddb.get_item(
            TableName=table, Key={'pk': {'S': key}},
            ConsistentRead=True, ReturnConsumedCapacity='TOTAL',
        )
        baseline_capacity += single['ConsumedCapacity']['CapacityUnits']

    resp = ddb.transact_get_items(
        TransactItems=[
            {'Get': {'TableName': table, 'Key': {'pk': {'S': 'tg-1'}}}},
            {'Get': {'TableName': table, 'Key': {'pk': {'S': 'tg-2'}}}},
        ],
        ReturnConsumedCapacity='TOTAL',
    )
    responses = resp['Responses']
    assert len(responses) == 2, f'expected 2 TransactGetItems responses, got {len(responses)}'
    assert responses[0]['Item']['v'] == {'N': '10'}, f'expected tg-1 v=10, got {responses[0]}'
    assert responses[1]['Item']['v'] == {'N': '20'}, f'expected tg-2 v=20, got {responses[1]}'

    transact_capacity = sum(c['CapacityUnits'] for c in resp['ConsumedCapacity'])
    assert transact_capacity == 2 * baseline_capacity, (
        f'TransactGetItems must consume exactly twice the RCU of the equivalent standalone '
        f'GetItem calls: expected {2 * baseline_capacity}, got {transact_capacity} '
        f'(standalone baseline {baseline_capacity})'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
