"""query-matching-nothing-still-consumes-read-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-matching-nothing-still-consumes-read-capacity"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A Query that matches no item still consumes the minimum read capacity for its read type. The
    zero-result path is exactly where an engine optimises the meter away."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}})
    cc = ddb.query(TableName=table, ReturnConsumedCapacity='TOTAL',
                   KeyConditionExpression='pk = :v',
                   ExpressionAttributeValues={':v': {'S': 'no-such-key'}})
    assert cc['Count'] == 0, f"the query must match nothing, got {cc['Count']}"
    assert cc['ConsumedCapacity']['CapacityUnits'] > 0, (
        f"a matchless Query still consumes capacity, got {cc['ConsumedCapacity']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
