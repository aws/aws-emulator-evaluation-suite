"""gsi-projection-keys-only."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-projection-keys-only"
GROUP = 'gsi'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GSI with KEYS_ONLY projection returns only key attributes."""
    ddb = ctx.client('dynamodb')
    gsi = [{'IndexName': 'region-index', 'KeySchema': [{'AttributeName': 'region', 'KeyType': 'HASH'}], 'Projection': {'ProjectionType': 'KEYS_ONLY'}}]
    table = ctx.unique_name('sim2real-behav-')
    _ks = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    _ad = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    for _ix in list(gsi):
        for _ke in _ix.get('KeySchema', []):
            if not any((_a['AttributeName'] == _ke['AttributeName'] for _a in _ad)):
                _ad.append({'AttributeName': _ke['AttributeName'], 'AttributeType': 'S'})
    _ctk = {'TableName': table, 'KeySchema': _ks, 'AttributeDefinitions': _ad, 'BillingMode': 'PAY_PER_REQUEST', 'Tags': [{'Key': 'sim2real', 'Value': CHECK}]}
    _ctk['GlobalSecondaryIndexes'] = gsi
    ddb.create_table(**_ctk)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'ko-1'}, 'region': {'S': 'us-east-1'}, 'extra': {'S': 'data'}})
    resp = _poll_until(
        probe=lambda: ddb.query(TableName=table, IndexName='region-index', KeyConditionExpression='#r = :v', ExpressionAttributeNames={'#r': 'region'}, ExpressionAttributeValues={':v': {'S': 'us-east-1'}}),
        predicate=lambda r: r['Count'] == 1,
        timeout_s=30,
        description='GSI propagation of the put item to region-index',
    )
    assert resp['Count'] == 1, f'expected exactly one item back from the region-index query, got Count={resp["Count"]!r}'
    item = resp['Items'][0]
    assert set(item) == {'pk', 'region'}, (
        f"a KEYS_ONLY projection must return exactly the base table's key ('pk') and the index "
        f"key ('region') and nothing else, got attribute set {sorted(item)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
