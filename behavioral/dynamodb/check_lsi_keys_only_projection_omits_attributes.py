"""lsi-keys-only-projection-omits-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-keys-only-projection-omits-attributes"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A strongly consistent read of a KEYS_ONLY LSI returns the table keys and the index sort key
    and nothing else, so an attribute that exists on the item is absent from the index read."""
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
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': '1'}, 'gpk': {'S': 'g1'}, 'lsk': {'N': '5'}, 'extra': {'S': 'e'}})
    item = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :v',
                     ExpressionAttributeValues={':v': {'S': 'a'}}, ConsistentRead=True)['Items'][0]
    assert set(item) == {'pk', 'sk', 'lsk'}, f'expected only keys, got {sorted(item)}'
    assert 'extra' not in item, 'a KEYS_ONLY index must not project a non-key attribute'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
