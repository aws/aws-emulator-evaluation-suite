"""gsi-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-query"
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
    """Query on a GSI returns items indexed by the GSI key."""
    ddb = ctx.client('dynamodb')
    gsi = [{'IndexName': 'email-index', 'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}], 'Projection': {'ProjectionType': 'ALL'}}]
    table = ctx.unique_name('sim2real-behav-')
    _ks = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    _ad = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    for _ix in list(gsi):
        for _ke in _ix.get('KeySchema', []):
            if not any((_a['AttributeName'] == _ke['AttributeName'] for _a in _ad)):
                _ad.append({'AttributeName': _ke['AttributeName'], 'AttributeType': 'S'})
    _ctk = {'TableName': table, 'KeySchema': _ks, 'AttributeDefinitions': _ad, 'BillingMode': 'PAY_PER_REQUEST'}
    _ctk['GlobalSecondaryIndexes'] = gsi
    _ctk['Tags'] = [{'Key': 'sim2real', 'Value': CHECK}]
    ddb.create_table(**_ctk)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'u1'}, 'email': {'S': 'alice@example.com'}, 'name': {'S': 'Alice'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'u2'}, 'email': {'S': 'bob@example.com'}, 'name': {'S': 'Bob'}})
    resp = _poll_until(
        probe=lambda: ddb.query(TableName=table, IndexName='email-index', KeyConditionExpression='email = :e', ExpressionAttributeValues={':e': {'S': 'alice@example.com'}}),
        predicate=lambda r: r['Count'] == 1,
        description='GSI propagation of the put item',
    )
    assert resp['Count'] == 1, f"expected exactly 1 item back from the GSI query, got {resp['Count']}: {resp['Items']!r}"
    item = resp['Items'][0]
    assert item['name'] == {'S': 'Alice'}, f"expected the GSI query to return Alice's item, got {item!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
