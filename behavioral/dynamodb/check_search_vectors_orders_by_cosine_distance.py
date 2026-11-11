"""search-vectors-orders-by-cosine-distance."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-vectors-orders-by-cosine-distance"
GROUP = 'vector'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors returns nearest-first by cosine DISTANCE: an identical vector scores 0, an
    orthogonal one 1 and an opposite one 2, so ordering and scale are both pinned."""
    import time

    ddb = ctx.client('dynamodb')
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
    for pk, v in {'a': [1, 0, 0], 'b': [0, 1, 0], 'c': [-1, 0, 0]}.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk},
                                            'embedding': {'L': [{'N': str(x)} for x in v]}})
    deadline = time.time() + 60
    results = []
    while time.time() < deadline:
        results = ddb.search_vectors(TableName=table, IndexName='cos', TopK=3,
                                     SearchVector=[{'N': '1'}, {'N': '0'}, {'N': '0'}]).get('SearchResults', [])
        if len(results) == 3:
            break
        time.sleep(1)
    scored = [(r['Item']['pk']['S'], float(r['Score'])) for r in results]
    assert [pk for pk, _ in scored] == ['a', 'b', 'c'], f'expected nearest-first a,b,c, got {scored}'
    assert abs(scored[0][1] - 0.0) < 1e-4, f'an identical vector has cosine distance 0, got {scored[0][1]}'
    assert abs(scored[1][1] - 1.0) < 1e-4, f'an orthogonal vector has cosine distance 1, got {scored[1][1]}'
    assert abs(scored[2][1] - 2.0) < 1e-4, f'an opposite vector has cosine distance 2, got {scored[2][1]}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
