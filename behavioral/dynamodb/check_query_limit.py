"""query-limit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-limit"
GROUP = 'query'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unfiltered Query with Limit=N returns at most N items, and since more items remain
    in the partition, reports a LastEvaluatedKey identifying the last item it evaluated.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'query-limit'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(10):
        ddb.put_item(TableName=table, Item={'pk': {'S': 'lim'}, 'sk': {'S': f'{i:03d}'}})
    resp = ddb.query(TableName=table, KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'lim'}}, Limit=3, ConsistentRead=True)
    assert len(resp['Items']) == 3, f'Limit=3 over a 10-item partition must return exactly 3 items, got {len(resp["Items"])}: {resp.get("Items")}'
    assert resp['Count'] == 3, f'Count must match the number of items returned, got {resp["Count"]}'
    assert resp['ScannedCount'] == 3, f'with no FilterExpression, ScannedCount must equal Count, got {resp["ScannedCount"]}'
    assert resp['Items'][0]['sk'] == {'S': '000'} and resp['Items'][2]['sk'] == {'S': '002'}, (
        f'Limit must take the first 3 items in sort-key order (000..002), got {[i["sk"] for i in resp["Items"]]}'
    )
    assert 'LastEvaluatedKey' in resp, 'a Limit-truncated Query with more items remaining must return a LastEvaluatedKey'
    assert resp['LastEvaluatedKey'] == {'pk': {'S': 'lim'}, 'sk': {'S': '002'}}, (
        f'LastEvaluatedKey must be the last evaluated key (sk 002), got {resp["LastEvaluatedKey"]}'
    )

    # Independent terminal read: page forward and confirm the cursor actually reaches the
    # remaining 7 items, disjoint from this page -- not just that a key-shaped value is present.
    rest = ddb.query(
        TableName=table,
        KeyConditionExpression='pk = :pk',
        ExpressionAttributeValues={':pk': {'S': 'lim'}},
        ExclusiveStartKey=resp['LastEvaluatedKey'],
        ConsistentRead=True,
    )
    assert 'LastEvaluatedKey' not in rest, f'the remaining 7 items fit in one page, got LastEvaluatedKey={rest.get("LastEvaluatedKey")}'
    assert {i['sk']['S'] for i in rest['Items']} == {f'{i:03d}' for i in range(3, 10)}, (
        f'paging past the Limit=3 cursor must yield exactly sk 003..009, got {sorted(i["sk"]["S"] for i in rest["Items"])}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
