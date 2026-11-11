"""lsi-query."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-query"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query on an LSI returns items sorted by the LSI sort key."""
    ddb = ctx.client('dynamodb')
    lsi = [{'IndexName': 'created-index', 'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'created_at', 'KeyType': 'RANGE'}], 'Projection': {'ProjectionType': 'ALL'}}]
    table = ctx.unique_name('sim2real-behav-')
    _ks = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    _ad = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    _ks.append({'AttributeName': 'sk', 'KeyType': 'RANGE'})
    _ad.append({'AttributeName': 'sk', 'AttributeType': 'S'})
    for _ix in list(lsi):
        for _ke in _ix.get('KeySchema', []):
            if not any((_a['AttributeName'] == _ke['AttributeName'] for _a in _ad)):
                _ad.append({'AttributeName': _ke['AttributeName'], 'AttributeType': 'S'})
    _ctk = {'TableName': table, 'KeySchema': _ks, 'AttributeDefinitions': _ad, 'BillingMode': 'PAY_PER_REQUEST'}
    _ctk['LocalSecondaryIndexes'] = lsi
    _ctk['Tags'] = [{'Key': 'sim2real', 'Value': CHECK}]
    ddb.create_table(**_ctk)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'lsi'}, 'sk': {'S': 'a'}, 'created_at': {'S': '2024-03-01'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'lsi'}, 'sk': {'S': 'b'}, 'created_at': {'S': '2024-01-01'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'lsi'}, 'sk': {'S': 'c'}, 'created_at': {'S': '2024-02-01'}})
    resp = ddb.query(TableName=table, IndexName='created-index', KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'lsi'}}, ConsistentRead=True)
    items = resp['Items']
    assert len(items) == 3, f'expected all 3 items back from the LSI query, got {len(items)}: {items}'
    dates = [item['created_at']['S'] for item in items]
    assert dates == sorted(dates), f'LSI query did not return items sorted by the LSI sort key created_at: {dates}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
