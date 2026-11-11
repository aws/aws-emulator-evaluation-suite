"""batch-write-item-delete-of-a-missing-item-still-consumes-a-write-unit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-write-item-delete-of-a-missing-item-still-consumes-a-write-unit"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """The same rule inside a batch: a DeleteRequest for a key that does not exist is billed a write
    unit, and the batch reports it per table."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    cc = ddb.batch_write_item(
        RequestItems={table: [{'DeleteRequest': {'Key': {'pk': {'S': 'ghost'}}}}]},
        ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']
    assert len(cc) == 1, f'expected one per-table capacity entry, got {cc}'
    assert cc[0]['CapacityUnits'] == 1.0, (
        f"a batched delete of a missing item still costs 1 unit, got {cc[0]['CapacityUnits']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
