"""deep-dynamodb-2-describe-item-count-lags-scan."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-describe-item-count-lags-scan"
GROUP = 'capacity'
SERVICES = ['dynamodb']
N_ITEMS = 25


def _table(ctx, ddb) -> str:
    name = ctx.unique_name('ddbexpr-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _scan_count(ddb, table) -> int:
    total = 0
    kwargs = {'TableName': table, 'Select': 'COUNT', 'ConsistentRead': True}
    while True:
        page = ddb.scan(**kwargs)
        total += page['Count']
        lek = page.get('LastEvaluatedKey')
        if not lek:
            return total
        kwargs['ExclusiveStartKey'] = lek


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c2")
def run(ctx) -> None:
    """DescribeTable.ItemCount is a periodic estimate; a consistent Scan counts all 25 writes.

    AWS updates ItemCount roughly every six hours, so 0 and 25 are both accepted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)

    for i in range(N_ITEMS):
        key = {'pk': {'S': f'item-{i:02d}'}}
        if i % 2:
            ddb.put_item(TableName=t, Item={**key, 'v': {'N': str(i)}})
        else:
            ddb.update_item(TableName=t, Key=key, UpdateExpression='SET v = :v',
                            ExpressionAttributeValues={':v': {'N': str(i)}})

    counted = _scan_count(ddb, t)
    assert counted == N_ITEMS, f'consistent Scan counted {counted!r} items; expected {N_ITEMS}'

    desc = ddb.describe_table(TableName=t)['Table']
    assert desc['TableStatus'] == 'ACTIVE', f'table status {desc["TableStatus"]!r}'
    assert desc['ItemCount'] == 0 or desc['ItemCount'] == N_ITEMS, (
        f'DescribeTable.ItemCount was {desc["ItemCount"]!r} seconds after {N_ITEMS} writes; real '
        f'DynamoDB still reports the periodic estimate 0 here, a live count is {N_ITEMS}'
    )
    assert desc['TableSizeBytes'] == 0 or (
        desc['ItemCount'] == N_ITEMS and desc['TableSizeBytes'] > 0
    ), (
        f'DescribeTable.TableSizeBytes was {desc["TableSizeBytes"]!r} with ItemCount '
        f'{desc["ItemCount"]!r}; expected the stale estimate 0 or a live non-zero size'
    )

    # Scan remains the real-time view after the metadata read.
    counted = _scan_count(ddb, t)
    assert counted == N_ITEMS, f'second Scan counted {counted!r}; expected {N_ITEMS}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
