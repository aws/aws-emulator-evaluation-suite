"""lsi-query-pagination-exclusive-start-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-query-pagination-exclusive-start-key"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """Paging a strongly consistent LSI Query with Limit returns LastEvaluatedKey carrying BOTH the
    table key and the index sort key, and resuming from it yields the remaining items exactly once."""
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
    for i in range(5):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'sk': {'S': f'{i}'}, 'lsk': {'N': str(i)}})
    first = ddb.query(TableName=table, IndexName='lsi1', Limit=2, KeyConditionExpression='pk = :v',
                      ExpressionAttributeValues={':v': {'S': 'a'}}, ConsistentRead=True)
    lek = first.get('LastEvaluatedKey')
    assert lek, 'a truncated LSI page must return LastEvaluatedKey'
    assert set(lek) >= {'pk', 'sk', 'lsk'}, (
        f'an LSI LastEvaluatedKey must carry the table key and the index key, got {sorted(lek)}'
    )
    seen = [i['sk']['S'] for i in first['Items']]
    page = first
    while page.get('LastEvaluatedKey'):
        page = ddb.query(TableName=table, IndexName='lsi1', Limit=2, KeyConditionExpression='pk = :v',
                         ExpressionAttributeValues={':v': {'S': 'a'}},
                         ExclusiveStartKey=page['LastEvaluatedKey'], ConsistentRead=True)
        seen.extend(i['sk']['S'] for i in page['Items'])
    assert sorted(seen) == ['0', '1', '2', '3', '4'], f'paging must yield each item once, got {sorted(seen)}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
