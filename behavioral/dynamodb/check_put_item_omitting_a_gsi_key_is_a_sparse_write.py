"""put-item-omitting-a-gsi-key-is-a-sparse-write."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-item-omitting-a-gsi-key-is-a-sparse-write"
GROUP = 'access_path'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """An item missing the GSI key is ACCEPTED and simply does not appear in the index -- sparse
    indexes are a modelled feature, so rejecting the write is over-strict."""
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
    ddb.put_item(TableName=table, Item={'pk': {'S': 'sparse'}, 'sk': {'S': '1'}, 'lsk': {'N': '1'}})
    assert ddb.get_item(TableName=table, Key={'pk': {'S': 'sparse'}, 'sk': {'S': '1'}},
                        ConsistentRead=True).get('Item'), 'the sparse item must exist in the table'
    # Positive control: an item that carries the GSI key is indexed (GSIs are eventually
    # consistent, so poll for it), and the index then holds that item and not the sparse one.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'dense'}, 'sk': {'S': '1'}, 'lsk': {'N': '1'},
                                        'gpk': {'S': 'indexed'}})
    deadline = time.monotonic() + max(1.0, min(60.0, (ctx.time_left() or 60.0) - 10.0))
    res = ddb.query(TableName=table, IndexName='gsi1', KeyConditionExpression='gpk = :v',
                    ExpressionAttributeValues={':v': {'S': 'indexed'}})
    while res['Count'] < 1 and time.monotonic() < deadline:
        time.sleep(2)
        res = ddb.query(TableName=table, IndexName='gsi1', KeyConditionExpression='gpk = :v',
                        ExpressionAttributeValues={':v': {'S': 'indexed'}})
    assert res['Count'] == 1, f"the item carrying gpk must appear in gsi1, got {res['Items']!r}"
    scanned = sorted(i['pk']['S'] for i in ddb.scan(TableName=table, IndexName='gsi1')['Items'])
    assert scanned == ['dense'], f"gsi1 must hold only the item with a GSI key, got {scanned!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
