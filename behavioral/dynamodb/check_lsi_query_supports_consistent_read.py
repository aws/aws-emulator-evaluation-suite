"""lsi-query-supports-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-query-supports-consistent-read"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """An LSI shares the base partition, so a strongly consistent Query through it is legal --
    the opposite of a GSI, and a target that refuses both is over-strict."""
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
    res = ddb.query(TableName=table, IndexName='lsi1', ConsistentRead=True,
                    KeyConditionExpression='pk = :v', ExpressionAttributeValues={':v': {'S': 'a'}})
    assert res['Count'] == 1, f"expected 1 item from a consistent LSI query, got {res['Count']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
