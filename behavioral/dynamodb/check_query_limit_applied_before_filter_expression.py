"""query-limit-applied-before-filter-expression."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-limit-applied-before-filter-expression"
GROUP = 'query'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Limit bounds the items examined, not returned: a Limit=2 Query whose only filter match is the fifth item returns
    Count 0, ScannedCount 2 and LastEvaluatedKey sk 002 on page one, and the match only on the third page.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'query-limit-before-filter'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Only sk '005' matches the filter; it sorts LAST in the partition.
    for i in range(1, 6):
        ddb.put_item(TableName=t, Item={
            'pk': {'S': 'u1'},
            'sk': {'S': f'{i:03d}'},
            'state': {'S': 'match' if i == 5 else 'other'},
        })

    filtered = {
        'TableName': t,
        'KeyConditionExpression': 'pk = :p',
        'FilterExpression': '#st = :m',
        'ExpressionAttributeNames': {'#st': 'state'},
        'ExpressionAttributeValues': {':p': {'S': 'u1'}, ':m': {'S': 'match'}},
        'ConsistentRead': True,
    }

    first = ddb.query(**filtered, Limit=2)
    assert first['Count'] == 0, (
        f'Limit=2 examines sk 001+002, neither of which matches the filter, so Count must be 0; '
        f'got Count={first["Count"]} Items={first.get("Items")}'
    )
    assert not first.get('Items'), f'Count=0 page must carry no Items, got {first.get("Items")}'
    assert first['ScannedCount'] == 2, (
        f'Limit=2 must be charged against items EXAMINED, so ScannedCount must be 2; '
        f'got {first["ScannedCount"]}'
    )
    assert 'LastEvaluatedKey' in first, (
        'a Limit-truncated Query must return a LastEvaluatedKey even when Count=0, otherwise '
        'the caller cannot reach the remaining items'
    )
    assert first['LastEvaluatedKey'] == {'pk': {'S': 'u1'}, 'sk': {'S': '002'}}, (
        f'LastEvaluatedKey must be the last EXAMINED key (sk 002), not the last matched key; '
        f'got {first["LastEvaluatedKey"]}'
    )

    # Page forward: the match is only found on the third page.
    pages = 1
    scanned_total = first['ScannedCount']
    matched: list[str] = []
    resp = first
    while 'LastEvaluatedKey' in resp:
        assert pages < 6, 'pagination did not terminate'
        resp = ddb.query(**filtered, Limit=2, ExclusiveStartKey=resp['LastEvaluatedKey'])
        pages += 1
        scanned_total += resp['ScannedCount']
        matched.extend(it['sk']['S'] for it in resp['Items'])

    assert pages == 3, f'5 items at Limit=2 must take exactly 3 pages, got {pages}'
    assert scanned_total == 5, f'total ScannedCount across pages must be 5, got {scanned_total}'
    assert matched == ['005'], f'exactly sk 005 must be returned across the pages, got {matched}'

    # Control: the same filtered Query with NO Limit returns the match in one page, with
    # ScannedCount reflecting the whole partition and no LastEvaluatedKey.
    unlimited = ddb.query(**filtered)
    assert unlimited['Count'] == 1, f'unlimited filtered Query must return 1 item, got {unlimited["Count"]}'
    assert unlimited['ScannedCount'] == 5, (
        f'unlimited filtered Query must report ScannedCount=5, got {unlimited["ScannedCount"]}'
    )
    assert 'LastEvaluatedKey' not in unlimited, (
        f'an exhausted Query must omit LastEvaluatedKey, got {unlimited.get("LastEvaluatedKey")}'
    )
    assert unlimited['Items'][0]['sk'] == {'S': '005'}, unlimited['Items']


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
