"""query-limit-at-partition-count-keeps-lastevaluatedkey-scan-limit-above-count-drops-it."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = 'query-limit-at-partition-count-keeps-lastevaluatedkey-scan-limit-above-count-drops-it'
GROUP = 'pagination'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with Limit equal to its partition's item count still returns a LastEvaluatedKey,
    whose next page is empty with none; Scan with Limit above the table's item count returns
    all items with no LastEvaluatedKey.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    written = ['001', '002', '003']
    for sk in written:
        ddb.put_item(TableName=t, Item={'pk': {'S': 'p1'}, 'sk': {'S': sk}})

    first = ddb.query(
        TableName=t, KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'p1'}},
        Limit=3, ConsistentRead=True,
    )
    assert first['Count'] == 3, f"expected Query Limit=3 over a 3-item partition to return Count 3, got {first['Count']!r}"
    first_sks = [i['sk']['S'] for i in first['Items']]
    assert first_sks == written, f"expected items in ascending sort-key order {written!r}, got {first_sks!r}"
    assert 'LastEvaluatedKey' in first, "Limit exactly equal to the partition's item count must still return a LastEvaluatedKey"
    assert first['LastEvaluatedKey'] == {'pk': {'S': 'p1'}, 'sk': {'S': '003'}}, (
        f"expected LastEvaluatedKey to name the last evaluated item (sk 003), got {first['LastEvaluatedKey']!r}"
    )

    second = ddb.query(
        TableName=t, KeyConditionExpression='pk = :pk', ExpressionAttributeValues={':pk': {'S': 'p1'}},
        Limit=3, ExclusiveStartKey=first['LastEvaluatedKey'], ConsistentRead=True,
    )
    assert second['Count'] == 0, f"expected the page after the boundary LastEvaluatedKey to be empty, got Count {second['Count']!r}"
    assert second['Items'] == [], f"expected no items past the boundary, got {second['Items']!r}"
    assert 'LastEvaluatedKey' not in second, f"expected no LastEvaluatedKey on the final empty page, got {second.get('LastEvaluatedKey')!r}"

    scanned = ddb.scan(TableName=t, Limit=5, ConsistentRead=True)
    assert scanned['Count'] == 3, f"expected Scan Limit=5 over a 3-item table to return Count 3, got {scanned['Count']!r}"
    assert scanned['ScannedCount'] == 3, f"expected unfiltered ScannedCount to equal Count 3, got {scanned['ScannedCount']!r}"
    scanned_sks = {i['sk']['S'] for i in scanned['Items']}
    assert scanned_sks == set(written), f"expected Scan to return every written item, got {scanned_sks!r}"
    assert 'LastEvaluatedKey' not in scanned, (
        f"expected no LastEvaluatedKey when Limit exceeds the table's item count, got {scanned.get('LastEvaluatedKey')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
