"""deep-dynamodb-1-ddbvec-consumed-capacity-reports-vector-bytes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-consumed-capacity-reports-vector-bytes"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [1.0, 0.0, 0.0, 0.0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """PutItem with ReturnConsumedCapacity=INDEXES reports VectorWriteRequestBytes (1024 at 4 dims, 6151 at 1536)
    for every vector index the attribute feeds and none for a non-vector write; SearchVectors reports
    VectorSearchRequestBytes when asked for TOTAL and omits ConsumedCapacity otherwise.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')

    def _vi(name, fn):
        return {'IndexName': name, 'VectorAttribute': {'AttributeName': 'emb'}, 'Dimensions': 4,
                'DistanceFunction': fn, 'Projection': {'ProjectionType': 'ALL'}}

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi('idx-cos', 'COSINE'), _vi('idx-dot', 'DOT_PRODUCT')],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)

    # A vector write: metered per vector index.
    put = ddb.put_item(TableName=table,
                       Item={'pk': {'S': 'v1'}, 'emb': {'L': _vec([1, 0, 0, 0])}},
                       ReturnConsumedCapacity='INDEXES')
    cc = put.get('ConsumedCapacity') or {}
    assert cc.get('TableName') == table, f'PutItem ConsumedCapacity was {cc!r}'
    per_index = cc.get('VectorIndexes') or {}
    assert set(per_index) == {'idx-cos', 'idx-dot'}, (
        f'a vector write must meter every index over the attribute; VectorIndexes was {per_index!r}'
    )
    for name, cap in per_index.items():
        assert cap.get('VectorWriteRequestBytes') == 1024.0, (
            f'{name}: VectorWriteRequestBytes was {cap.get("VectorWriteRequestBytes")!r} for dims=4'
        )

    # A large vector, over a dedicated table/index, to see whether the meter scales with dims.
    table2 = ctx.unique_name('sim2real-behav-ddbvec-large-')
    ddb.create_table(
        TableName=table2,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[_vi2('idx-big', 1536, 'COSINE')],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table2))
    _wait_vector_table_active(ddb, table2)
    put2 = ddb.put_item(TableName=table2,
                        Item={'pk': {'S': 'v1'}, 'emb': {'L': _vec([1.0] * 1536)}},
                        ReturnConsumedCapacity='INDEXES')
    cc2 = (put2.get('ConsumedCapacity') or {}).get('VectorIndexes') or {}
    wb2 = (cc2.get('idx-big') or {}).get('VectorWriteRequestBytes')
    assert wb2 == 6151.0, f'idx-big: VectorWriteRequestBytes was {wb2!r} for dims=1536'

    # A non-vector write on the same table: no vector meter.
    plain = ddb.put_item(TableName=table, Item={'pk': {'S': 'plain'}, 'note': {'S': 'no vector'}},
                         ReturnConsumedCapacity='INDEXES')
    pcc = plain.get('ConsumedCapacity') or {}
    assert pcc.get('TableName') == table and pcc.get('CapacityUnits', 0) > 0, (
        f'the non-vector PutItem reported ConsumedCapacity {pcc!r}'
    )
    assert 'VectorIndexes' not in pcc, (
        f'a write touching no vector attribute was metered against vector indexes: {pcc!r}'
    )

    # Search meter, requested.
    res = []
    deadline = time.time() + 90
    out = {}
    while time.time() < deadline:
        out = ddb.search_vectors(TableName=table, IndexName='idx-cos', TopK=5,
                                 SearchVector=_vec(_QUERY), ReturnConsumedCapacity='TOTAL')
        res = out.get('SearchResults', [])
        if res:
            break
        time.sleep(1)
    assert [r['Item']['pk']['S'] for r in res] == ['v1'], (
        f'only the vector item is searchable; got {[r["Item"]["pk"]["S"] for r in res]!r}'
    )
    scc = out.get('ConsumedCapacity') or {}
    sb = scc.get('VectorSearchRequestBytes')
    assert isinstance(sb, (int, float)) and sb > 0, (
        f'SearchVectors ConsumedCapacity.VectorSearchRequestBytes was {sb!r} (whole: {scc!r})'
    )

    # Search meter, not requested: absent.
    quiet = ddb.search_vectors(TableName=table, IndexName='idx-dot', TopK=5,
                               SearchVector=_vec(_QUERY))
    assert [r['Item']['pk']['S'] for r in quiet['SearchResults']] == ['v1'], (
        f'idx-dot search returned {quiet["SearchResults"]!r}'
    )
    assert 'ConsumedCapacity' not in quiet, (
        f'ConsumedCapacity returned without ReturnConsumedCapacity: {quiet.get("ConsumedCapacity")!r}'
    )


def _vi2(name, dims, fn):
    return {'IndexName': name, 'VectorAttribute': {'AttributeName': 'emb'}, 'Dimensions': dims,
            'DistanceFunction': fn, 'Projection': {'ProjectionType': 'ALL'}}


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


def _wait_vector_table_active(ddb, table, timeout_s=240):
    deadline = time.time() + timeout_s
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    tbl = ddb.describe_table(TableName=table)['Table']
    assert tbl.get('VectorIndexes'), (
        'CreateTable accepted VectorIndexes but DescribeTable reports none - the vector indexes '
        'were silently dropped'
    )
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if tbl['TableStatus'] == 'ACTIVE' and all(
                v.get('IndexStatus') == 'ACTIVE' for v in tbl.get('VectorIndexes', [])):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f'table/vector indexes never became ACTIVE: {tbl["TableStatus"]!r} '
        f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in tbl.get("VectorIndexes", [])]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
