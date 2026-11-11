"""query-on-index-consumed-capacity-attributes-the-index."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-on-index-consumed-capacity-attributes-the-index"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """ReturnConsumedCapacity=INDEXES on a Query through a GSI attributes the read to the INDEX
    arm and charges the table nothing -- the arm breakdown, not just a total."""
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
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g1'}, 'lsk': {'N': '5'}})
    cc = ddb.query(TableName=table, IndexName='gsi1', ReturnConsumedCapacity='INDEXES',
                   KeyConditionExpression='gpk = :v', ExpressionAttributeValues={':v': {'S': 'g1'}})['ConsumedCapacity']
    assert 'GlobalSecondaryIndexes' in cc, f'expected a GlobalSecondaryIndexes arm, got {sorted(cc)}'
    assert 'gsi1' in cc['GlobalSecondaryIndexes'], f"expected the gsi1 arm, got {sorted(cc['GlobalSecondaryIndexes'])}"
    assert cc['GlobalSecondaryIndexes']['gsi1']['CapacityUnits'] > 0, 'the index arm must be charged'
    assert cc.get('Table', {}).get('CapacityUnits', 0) == 0, (
        f"a GSI read charges the table nothing, got {cc.get('Table')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
