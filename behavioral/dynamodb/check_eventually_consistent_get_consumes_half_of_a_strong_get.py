"""eventually-consistent-get-consumes-half-of-a-strong-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "eventually-consistent-get-consumes-half-of-a-strong-get"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """An eventually consistent read consumes half the units of a strongly consistent one, which is
    why a table provisioned for N consistent reads serves 2N eventually consistent ones."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}})
    strong = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}}, ConsistentRead=True,
                          ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']['CapacityUnits']
    eventual = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}},
                            ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']['CapacityUnits']
    assert eventual == strong / 2, (
        f'an eventually consistent read is half a strong one: expected {strong / 2}, got {eventual}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
