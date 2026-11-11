"""gsi-projection-include."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-projection-include"
GROUP = 'gsi'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GSI with INCLUDE projection returns only specified non-key attributes."""
    ddb = ctx.client('dynamodb')
    gsi = [{'IndexName': 'cat-index', 'KeySchema': [{'AttributeName': 'category', 'KeyType': 'HASH'}], 'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['title']}}]
    table = ctx.unique_name('sim2real-behav-')
    _ks = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    _ad = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    for _ix in list(gsi):
        for _ke in _ix.get('KeySchema', []):
            if not any((_a['AttributeName'] == _ke['AttributeName'] for _a in _ad)):
                _ad.append({'AttributeName': _ke['AttributeName'], 'AttributeType': 'S'})
    _ctk = {'TableName': table, 'KeySchema': _ks, 'AttributeDefinitions': _ad, 'BillingMode': 'PAY_PER_REQUEST'}
    _ctk['GlobalSecondaryIndexes'] = gsi
    _ctk['Tags'] = [{'Key': 'sim2real-check', 'Value': CHECK}]
    ddb.create_table(**_ctk)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'inc-1'}, 'category': {'S': 'books'}, 'title': {'S': 'Book1'}, 'secret': {'S': 'hidden'}})

    base = ddb.get_item(TableName=table, Key={'pk': {'S': 'inc-1'}}, ConsistentRead=True)['Item']
    assert base['secret']['S'] == 'hidden', (
        f"the base item never carried 'secret', so the absence asserted below would be vacuous: {base!r}"
    )

    resp = _poll_until(probe=lambda: ddb.query(TableName=table, IndexName='cat-index', KeyConditionExpression='category = :c', ExpressionAttributeValues={':c': {'S': 'books'}}), predicate=lambda r: r['Count'] == 1, timeout_s=30, description='GSI propagation')
    assert resp['Count'] == 1, f"expected exactly one item from the GSI query, got {resp['Count']}: {resp['Items']!r}"
    item = resp['Items'][0]
    assert item.get('title') == {'S': 'Book1'}, f"expected the INCLUDEd 'title' attribute to be 'Book1', got {item.get('title')!r}"
    assert 'secret' not in item, f"a non-projected attribute leaked out of the INCLUDE GSI: {item!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
