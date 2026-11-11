"""delete-item-on-a-missing-item-still-consumes-a-write-unit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-item-on-a-missing-item-still-consumes-a-write-unit"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A DeleteItem against a key that was never written is a no-op on state but NOT free: it still
    consumes a write unit. An engine that short-circuits the delete reports zero and diverges."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    cc = ddb.delete_item(TableName=table, Key={'pk': {'S': 'ghost'}},
                         ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']
    assert cc['CapacityUnits'] == 1.0, (
        f"deleting a non-existent item still costs 1 write unit, got {cc['CapacityUnits']}"
    )
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, 'the table must stay empty'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
