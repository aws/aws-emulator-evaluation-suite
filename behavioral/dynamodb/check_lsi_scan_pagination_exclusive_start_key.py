"""lsi-scan-pagination-exclusive-start-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-scan-pagination-exclusive-start-key"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """Scanning an LSI pages the same way a Query does: LastEvaluatedKey resumes the scan and no
    item is returned twice or dropped."""
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
        ddb.put_item(TableName=table, Item={'pk': {'S': f'p{i}'}, 'sk': {'S': '1'}, 'lsk': {'N': str(i)}})
    seen, page, guard = [], None, 0
    while True:
        kw = {'TableName': table, 'IndexName': 'lsi1', 'Limit': 2}
        if page:
            kw['ExclusiveStartKey'] = page
        res = ddb.scan(**kw)
        seen.extend(i['pk']['S'] for i in res['Items'])
        page = res.get('LastEvaluatedKey')
        guard += 1
        assert guard < 20, 'scan paging did not terminate'
        if not page:
            break
    assert sorted(seen) == ['p0', 'p1', 'p2', 'p3', 'p4'], f'expected each item once, got {sorted(seen)}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
