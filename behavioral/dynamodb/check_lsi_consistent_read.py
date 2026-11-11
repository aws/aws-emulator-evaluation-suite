"""lsi-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-consistent-read"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LSI supports ConsistentRead=True (unlike GSI)."""
    ddb = ctx.client('dynamodb')
    lsi = [{'IndexName': 'ts-index', 'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'ts', 'KeyType': 'RANGE'}], 'Projection': {'ProjectionType': 'ALL'}}]
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
    item = {'pk': {'S': 'lsi-cr'}, 'sk': {'S': 'x'}, 'ts': {'S': '100'}}
    ddb.put_item(TableName=table, Item=item)
    # No sleep and no retry: a query against an LSI with ConsistentRead=True must see the write it
    # immediately followed, and must not be rejected the way the identical flag is on a GSI.
    resp = ddb.query(TableName=table, IndexName='ts-index', KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'lsi-cr'}}, ConsistentRead=True)
    assert resp['Items'] == [item], (
        f"ConsistentRead=True query against the LSI immediately after the write it followed "
        f"returned {resp['Items']!r}, expected the single item just written back verbatim "
        f"{[item]!r}. A target that rejects ConsistentRead on an LSI (as it correctly does for a "
        f"GSI), or that returns it stale or empty, is not honoring LSI strong consistency."
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
