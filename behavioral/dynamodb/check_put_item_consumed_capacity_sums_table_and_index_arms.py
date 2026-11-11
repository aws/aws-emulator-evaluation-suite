"""put-item-consumed-capacity-sums-table-and-index-arms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-consumed-capacity-sums-table-and-index-arms"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A write that lands in both indexes reports a table arm and both index arms, and the total
    is their sum -- so an emulator reporting only the table write is short."""
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
                      Item={'pk': {'S': 'a'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g1'}, 'lsk': {'N': '5'}})['ConsumedCapacity']
    table_arm = cc.get('Table', {}).get('CapacityUnits', 0)
    gsi_arm = cc.get('GlobalSecondaryIndexes', {}).get('gsi1', {}).get('CapacityUnits', 0)
    lsi_arm = cc.get('LocalSecondaryIndexes', {}).get('lsi1', {}).get('CapacityUnits', 0)
    assert table_arm > 0, f'expected a table arm, got {cc.get("Table")}'
    assert gsi_arm > 0, f'expected a gsi1 arm, got {cc.get("GlobalSecondaryIndexes")}'
    assert lsi_arm > 0, f'expected an lsi1 arm, got {cc.get("LocalSecondaryIndexes")}'
    assert cc['CapacityUnits'] == table_arm + gsi_arm + lsi_arm, (
        f"total {cc['CapacityUnits']} must equal {table_arm} + {gsi_arm} + {lsi_arm}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
