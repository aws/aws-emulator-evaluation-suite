"""put-item-sparse-write-charges-no-index-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-sparse-write-charges-no-index-capacity"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A write that misses both index keys is charged for the table only: no index arm appears,
    because nothing was written to an index."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    cc = ddb.put_item(TableName=table, ReturnConsumedCapacity='INDEXES',
                      Item={'pk': {'S': 'sparse'}, 'sk': {'S': '1'}})['ConsumedCapacity']
    assert cc.get('Table', {}).get('CapacityUnits', 0) > 0, 'the table write must still be charged'
    assert not cc.get('GlobalSecondaryIndexes'), (
        f"a write missing the GSI key must charge no GSI arm, got {cc.get('GlobalSecondaryIndexes')}"
    )
    assert not cc.get('LocalSecondaryIndexes'), (
        f"a write missing the LSI key must charge no LSI arm, got {cc.get('LocalSecondaryIndexes')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
