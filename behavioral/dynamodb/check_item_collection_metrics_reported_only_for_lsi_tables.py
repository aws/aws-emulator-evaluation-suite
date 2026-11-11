"""item-collection-metrics-reported-only-for-lsi-tables."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "item-collection-metrics-reported-only-for-lsi-tables"
GROUP = 'limits'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReturnItemCollectionMetrics=SIZE on a table with an LSI reports the partition key alone and an ordered
    two-value size estimate; a table without an LSI, or a write that does not request them, reports none.
    """
    ddb = ctx.client('dynamodb')

    with_lsi = ctx.unique_name('sim2real-behav-lsi-')
    ddb.create_table(
        TableName=with_lsi,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
            {'AttributeName': 'li', 'AttributeType': 'S'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=with_lsi))

    without_lsi = ctx.unique_name('sim2real-behav-plain-')
    ddb.create_table(
        TableName=without_lsi,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=without_lsi))

    ddb.get_waiter('table_exists').wait(TableName=with_lsi, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.get_waiter('table_exists').wait(TableName=without_lsi, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    reported = ddb.put_item(
        TableName=with_lsi,
        Item={'pk': {'S': 'coll'}, 'sk': {'N': '1'}, 'li': {'S': 'x'}},
        ReturnItemCollectionMetrics='SIZE',
    )
    metrics = reported.get('ItemCollectionMetrics')
    assert metrics, f'a write to an LSI-bearing table must report item-collection metrics, got {metrics!r}'
    assert metrics.get('ItemCollectionKey') == {'pk': {'S': 'coll'}}, (
        f'the collection key must be the partition key alone, got {metrics.get("ItemCollectionKey")!r}'
    )
    estimate = metrics.get('SizeEstimateRangeGB')
    assert isinstance(estimate, list) and len(estimate) == 2, (
        f'SizeEstimateRangeGB must be a two-element lower/upper bound, got {estimate!r}'
    )
    assert estimate[0] <= estimate[1], f'the estimate range must be ordered, got {estimate!r}'

    plain = ddb.put_item(
        TableName=without_lsi,
        Item={'pk': {'S': 'coll'}, 'sk': {'N': '1'}},
        ReturnItemCollectionMetrics='SIZE',
    )
    assert 'ItemCollectionMetrics' not in plain, (
        f'a table with no LSI has no item collection, so nothing may be reported, '
        f'got {plain.get("ItemCollectionMetrics")!r}'
    )

    # Not requesting the metrics suppresses them even where a collection exists,
    # so the field tracks the request parameter and not merely the table shape.
    unrequested = ddb.put_item(
        TableName=with_lsi,
        Item={'pk': {'S': 'coll'}, 'sk': {'N': '2'}, 'li': {'S': 'y'}},
    )
    assert 'ItemCollectionMetrics' not in unrequested, (
        f'item-collection metrics must be absent when not requested, '
        f'got {unrequested.get("ItemCollectionMetrics")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
