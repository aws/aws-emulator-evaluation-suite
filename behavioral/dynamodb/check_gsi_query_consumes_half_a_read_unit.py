"""gsi-query-consumes-half-a-read-unit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "gsi-query-consumes-half-a-read-unit"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A GSI is eventually consistent by construction, so a GSI Query consumes half a read unit --
    half what the same read costs strongly consistently on the base table."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'gpk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{'IndexName': 'gsi1',
                                 'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
                                 'Projection': {'ProjectionType': 'ALL'}}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'gpk': {'S': 'g'}})
    strong = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}}, ConsistentRead=True,
                          ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']['CapacityUnits']
    idx = ddb.query(TableName=table, IndexName='gsi1', ReturnConsumedCapacity='TOTAL',
                    KeyConditionExpression='gpk = :v',
                    ExpressionAttributeValues={':v': {'S': 'g'}})['ConsumedCapacity']
    assert idx['CapacityUnits'] == strong / 2, (
        f"a GSI query costs half a strong read: expected {strong / 2}, got {idx['CapacityUnits']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
