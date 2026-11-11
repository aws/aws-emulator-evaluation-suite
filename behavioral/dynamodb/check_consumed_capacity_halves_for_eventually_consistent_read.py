"""consumed-capacity-halves-for-eventually-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "consumed-capacity-halves-for-eventually-consistent-read"
GROUP = 'limits'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A strongly consistent read of a sub-4KB item bills exactly 1.0 RCU and the eventually consistent read
    of it exactly 0.5, and a read without ReturnConsumedCapacity reports no ConsumedCapacity."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={'pk': {'S': 'k'}, 'a': {'S': 'small'}})

    strong = ddb.get_item(
        TableName=t, Key={'pk': {'S': 'k'}}, ConsistentRead=True, ReturnConsumedCapacity='TOTAL'
    )
    assert strong.get('Item'), 'strongly consistent read must return the item it is billing for'
    strong_cu = (strong.get('ConsumedCapacity') or {}).get('CapacityUnits')
    assert strong_cu == 1.0, f'strongly consistent sub-4KB read must bill 1.0, got {strong_cu!r}'

    eventual = ddb.get_item(
        TableName=t, Key={'pk': {'S': 'k'}}, ConsistentRead=False, ReturnConsumedCapacity='TOTAL'
    )
    eventual_cu = (eventual.get('ConsumedCapacity') or {}).get('CapacityUnits')
    assert eventual_cu == 0.5, f'eventually consistent sub-4KB read must bill 0.5, got {eventual_cu!r}'
    assert eventual_cu * 2 == strong_cu, (
        f'eventual read must cost exactly half a strong read, got {eventual_cu!r} vs {strong_cu!r}'
    )

    # Omitting ReturnConsumedCapacity must suppress the field entirely, so a
    # responder cannot pass the assertions above by always populating it.
    silent = ddb.get_item(TableName=t, Key={'pk': {'S': 'k'}}, ConsistentRead=True)
    assert 'ConsumedCapacity' not in silent, (
        f'ConsumedCapacity must be absent when not requested, got {silent.get("ConsumedCapacity")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
