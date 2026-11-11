"""item-collection-metrics-scoped-to-lsi-tables-and-requests."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "item-collection-metrics-scoped-to-lsi-tables-and-requests"
GROUP = 'lsi'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With ReturnItemCollectionMetrics=SIZE on an LSI table, Put/Update/DeleteItem report
    ItemCollectionMetrics keyed by the partition key alone; NONE, an omitted parameter, or a table
    without an LSI report nothing."""
    ddb = ctx.client('dynamodb')

    with_lsi = ctx.unique_name('sim2real-behav-icm-')
    ddb.create_table(
        TableName=with_lsi,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': n, 'AttributeType': 'S'} for n in ('pk', 'sk', 'l1')],
        BillingMode='PAY_PER_REQUEST',
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                          {'AttributeName': 'l1', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=with_lsi))

    no_lsi = ctx.unique_name('sim2real-behav-icm-nolsi-')
    ddb.create_table(
        TableName=no_lsi,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': n, 'AttributeType': 'S'} for n in ('pk', 'sk')],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=no_lsi))

    ddb.get_waiter('table_exists').wait(TableName=with_lsi, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.get_waiter('table_exists').wait(TableName=no_lsi, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # The key schema is read, not assumed: the assertion below is an identity against the table's
    # own declared hash key, so it cannot pass by coincidence of naming.
    schema = {k['KeyType']: k['AttributeName']
              for k in ddb.describe_table(TableName=with_lsi)['Table']['KeySchema']}
    assert schema.get('HASH') == 'pk' and schema.get('RANGE') == 'sk', (
        f'setup: the LSI table must have a composite key schema to make this assertion meaningful, '
        f'got {schema!r}'
    )

    def _assert_collection(metrics, op):
        assert metrics is not None, (
            f'{op} with ReturnItemCollectionMetrics=SIZE on an LSI-bearing table must report '
            f'ItemCollectionMetrics'
        )
        key = metrics.get('ItemCollectionKey')
        assert key is not None, (
            f'{op} must report the collection it touched under ItemCollectionKey, got members '
            f'{sorted(metrics)!r}'
        )
        assert list(key) == [schema['HASH']], (
            f'{op} must identify the item collection by the PARTITION key alone '
            f'({schema["HASH"]!r}); the range key {schema["RANGE"]!r} is not part of a collection '
            f'identity. Got {key!r}'
        )
        size = metrics.get('SizeEstimateRangeGB')
        assert isinstance(size, list) and len(size) == 2, (
            f'{op} must report SizeEstimateRangeGB as exactly [lower, upper], got {size!r}'
        )
        assert size[0] <= size[1], (
            f'{op} reported SizeEstimateRangeGB bounds out of order: {size!r}'
        )
        return key

    # --- reported by all three mutating operations on the LSI table ---
    put = ddb.put_item(
        TableName=with_lsi,
        Item={'pk': {'S': 'coll-a'}, 'sk': {'S': 's1'}, 'l1': {'S': 'x'}},
        ReturnItemCollectionMetrics='SIZE')
    put_key = _assert_collection(put.get('ItemCollectionMetrics'), 'PutItem')
    assert put_key == {schema['HASH']: {'S': 'coll-a'}}, (
        f'PutItem must report the partition key VALUE it wrote to, got {put_key!r}'
    )

    upd = ddb.update_item(
        TableName=with_lsi, Key={'pk': {'S': 'coll-a'}, 'sk': {'S': 's1'}},
        UpdateExpression='SET extra = :e', ExpressionAttributeValues={':e': {'S': '1'}},
        ReturnItemCollectionMetrics='SIZE')
    _assert_collection(upd.get('ItemCollectionMetrics'), 'UpdateItem')

    ddb.put_item(TableName=with_lsi, Item={'pk': {'S': 'coll-b'}, 'sk': {'S': 's1'}})
    dele = ddb.delete_item(
        TableName=with_lsi, Key={'pk': {'S': 'coll-b'}, 'sk': {'S': 's1'}},
        ReturnItemCollectionMetrics='SIZE')
    del_key = _assert_collection(dele.get('ItemCollectionMetrics'), 'DeleteItem')
    assert del_key == {schema['HASH']: {'S': 'coll-b'}}, (
        f'DeleteItem must report the partition key VALUE it removed from, got {del_key!r}'
    )

    # --- not reported when it was not asked for ---
    none = ddb.put_item(TableName=with_lsi, Item={'pk': {'S': 'coll-c'}, 'sk': {'S': 's1'}},
                        ReturnItemCollectionMetrics='NONE')
    assert 'ItemCollectionMetrics' not in none, (
        f'ReturnItemCollectionMetrics=NONE must suppress the member entirely, got '
        f'{none.get("ItemCollectionMetrics")!r}'
    )
    omitted = ddb.put_item(TableName=with_lsi, Item={'pk': {'S': 'coll-d'}, 'sk': {'S': 's1'}})
    assert 'ItemCollectionMetrics' not in omitted, (
        f'omitting ReturnItemCollectionMetrics must suppress the member entirely, got '
        f'{omitted.get("ItemCollectionMetrics")!r}'
    )

    # --- not reported at all where there is no item collection to measure ---
    for op, resp in (
        ('PutItem', ddb.put_item(TableName=no_lsi,
                                 Item={'pk': {'S': 'plain'}, 'sk': {'S': 's1'}},
                                 ReturnItemCollectionMetrics='SIZE')),
        ('UpdateItem', ddb.update_item(TableName=no_lsi,
                                       Key={'pk': {'S': 'plain'}, 'sk': {'S': 's1'}},
                                       UpdateExpression='SET extra = :e',
                                       ExpressionAttributeValues={':e': {'S': '1'}},
                                       ReturnItemCollectionMetrics='SIZE')),
        ('DeleteItem', ddb.delete_item(TableName=no_lsi,
                                       Key={'pk': {'S': 'plain'}, 'sk': {'S': 's1'}},
                                       ReturnItemCollectionMetrics='SIZE')),
    ):
        assert 'ItemCollectionMetrics' not in resp, (
            f'{op} on a table with NO local secondary index has no item collection to size and must '
            f'report nothing even when SIZE is requested, got {resp.get("ItemCollectionMetrics")!r}'
        )

    # --- the writes those metrics described really happened ---
    got = ddb.get_item(TableName=with_lsi, Key={'pk': {'S': 'coll-a'}, 'sk': {'S': 's1'}},
                       ConsistentRead=True).get('Item', {})
    assert got.get('extra') == {'S': '1'}, (
        f'the PutItem and UpdateItem that reported metrics must have taken effect, got {got!r}'
    )
    removed = ddb.get_item(TableName=with_lsi, Key={'pk': {'S': 'coll-b'}, 'sk': {'S': 's1'}},
                           ConsistentRead=True)
    assert 'Item' not in removed, (
        f'the DeleteItem that reported metrics must have removed the item, got {removed.get("Item")!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
