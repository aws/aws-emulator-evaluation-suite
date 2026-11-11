"""create-table-with-vector-index-is-described-back."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-table-with-vector-index-is-described-back"
GROUP = 'vector'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable with VectorIndexes is reflected by DescribeTable with the dimensions, the
    distance function and the vector attribute it was created with."""
    import time

    ddb = ctx.client('dynamodb')
    account = ctx.client('sts').get_caller_identity()['Account']
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'cos',
            'VectorAttribute': {'AttributeName': 'embedding'},
            'Dimensions': 3,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    # Fail FAST when CreateTable ignored `VectorIndexes` outright: an index that is absent
    # immediately after create is never going to appear. Poll only while the
    # index EXISTS but is still backfilling, which is the state a real create passes through.
    described = ddb.describe_table(TableName=table)['Table'].get('VectorIndexes', [])
    assert described, (
        'CreateTable accepted VectorIndexes but DescribeTable reports none, so the vector index '
        'was silently dropped'
    )
    deadline = time.time() + 120
    while time.time() < deadline and described[0].get('IndexStatus') != 'ACTIVE':
        time.sleep(1)
        described = ddb.describe_table(TableName=table)['Table'].get('VectorIndexes', [])
        assert described, 'the vector index disappeared while it was backfilling'
    assert described[0].get('IndexStatus') == 'ACTIVE', (
        f"the vector index never became ACTIVE: {described[0].get('IndexStatus')!r}"
    )
    idx = described[0]
    assert idx['IndexName'] == 'cos', f"expected IndexName cos, got {idx.get('IndexName')}"
    assert idx['Dimensions'] == 3, f"expected Dimensions 3, got {idx.get('Dimensions')}"
    assert idx['DistanceFunction'] == 'COSINE', f"expected COSINE, got {idx.get('DistanceFunction')}"
    assert idx['VectorAttribute']['AttributeName'] == 'embedding', (
        f"expected the embedding attribute, got {idx.get('VectorAttribute')}"
    )
    assert idx['VectorAttribute'] == {'AttributeName': 'embedding'}, (
        f"expected VectorAttribute to hold only AttributeName, got {idx['VectorAttribute']!r}"
    )
    assert idx['Projection'] == {'ProjectionType': 'ALL'}, (
        f"expected Projection {{'ProjectionType': 'ALL'}}, got {idx['Projection']!r}"
    )
    assert 'SearchSchema' not in idx, (
        f"no SearchSchema was configured, but DescribeTable returned one: {idx.get('SearchSchema')!r}"
    )
    assert 'Backfilling' not in idx, (
        f"expected no Backfilling field once ACTIVE and backfill complete, got {idx.get('Backfilling')!r}"
    )
    assert idx['IndexSizeBytes'] == 0, f"expected IndexSizeBytes 0 on an empty index, got {idx.get('IndexSizeBytes')!r}"
    assert idx['ItemCount'] == 0, f"expected ItemCount 0 on an empty index, got {idx.get('ItemCount')!r}"
    expected_arn = f'arn:aws:dynamodb:{ctx.region}:{account}:table/{table}/index/cos'
    assert idx['IndexArn'] == expected_arn, f"expected IndexArn {expected_arn!r}, got {idx.get('IndexArn')!r}"
    assert set(idx) == {
        'IndexName', 'Projection', 'VectorAttribute', 'Dimensions', 'DistanceFunction',
        'IndexStatus', 'IndexSizeBytes', 'ItemCount', 'IndexArn',
    }, f"unexpected VectorIndexDescription fields: {sorted(idx)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
