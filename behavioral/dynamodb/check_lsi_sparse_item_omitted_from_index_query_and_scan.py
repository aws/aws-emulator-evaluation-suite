"""lsi-sparse-item-omitted-from-index-query-and-scan."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-sparse-item-omitted-from-index-query-and-scan"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """An item with no LSI sort key is left out of an LSI Query and an LSI Scan, while the base
    table's Query and Scan still return it."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={'pk': {'S': 'item'}, 'sk': {'S': '1'}, 'lsk': {'N': '1'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'item'}, 'sk': {'S': '2'}})

    lsi_query = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :pk',
                         ExpressionAttributeValues={':pk': {'S': 'item'}}, ConsistentRead=True)
    lsi_query_sks = sorted(i['sk']['S'] for i in lsi_query['Items'])
    assert lsi_query_sks == ['1'], (
        f"the item without lsk must be left out of the LSI Query, got sk values {lsi_query_sks}"
    )

    lsi_scan = ddb.scan(TableName=table, IndexName='lsi1', ConsistentRead=True)
    lsi_scan_sks = sorted(i['sk']['S'] for i in lsi_scan['Items'])
    assert lsi_scan_sks == ['1'], (
        f"the item without lsk must be left out of the LSI Scan, got sk values {lsi_scan_sks}"
    )

    base_query = ddb.query(TableName=table, KeyConditionExpression='pk = :pk',
                           ExpressionAttributeValues={':pk': {'S': 'item'}}, ConsistentRead=True)
    base_query_sks = sorted(i['sk']['S'] for i in base_query['Items'])
    assert base_query_sks == ['1', '2'], (
        f"the base table Query must still return both items, got sk values {base_query_sks}"
    )

    base_scan = ddb.scan(TableName=table, ConsistentRead=True)
    base_scan_sks = sorted(i['sk']['S'] for i in base_scan['Items'])
    assert base_scan_sks == ['1', '2'], (
        f"the base table Scan must still return both items, got sk values {base_scan_sks}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
