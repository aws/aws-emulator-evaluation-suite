"""search-vectors-consumed-capacity-is-vector-bytes-only-floored-and-scales."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-vectors-consumed-capacity-is-vector-bytes-only-floored-and-scales"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY_SMALL = [1.0, 0.0, 0.0, 0.0]
_DIMS_BIG = 128
_N = 25


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors ConsumedCapacity carries only VectorSearchRequestBytes, floored at 1024,
    and that figure grows with TopK and with returning the searched vector attribute itself.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[
            {'IndexName': 'idx-small', 'VectorAttribute': {'AttributeName': 'emb_small'},
             'Dimensions': 4, 'DistanceFunction': 'COSINE', 'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': 'idx-big', 'VectorAttribute': {'AttributeName': 'emb_big'},
             'Dimensions': _DIMS_BIG, 'DistanceFunction': 'COSINE',
             'Projection': {'ProjectionType': 'ALL'}},
        ],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)

    query_big = _vec([1.0 if j == 0 else 0.0 for j in range(_DIMS_BIG)])
    for i in range(_N):
        big = [1.0 if j == 0 else 0.0 for j in range(_DIMS_BIG)]
        big[1] = float(i) * 0.001
        ddb.put_item(TableName=table, Item={
            'pk': {'S': f'v{i}'},
            'emb_small': {'L': _vec(_QUERY_SMALL)},
            'emb_big': {'L': _vec(big)},
        })

    # Shape and floor: a minimal search on a 4-dim index reports exactly one key, at 1024.
    floor_cc = _search_until(ddb, table, 'idx-small', 1, _vec(_QUERY_SMALL),
                             lambda res: len(res) >= 1)
    assert set(floor_cc) == {'VectorSearchRequestBytes'}, (
        f'SearchVectors ConsumedCapacity keys were {sorted(floor_cc)}, expected only '
        f'VectorSearchRequestBytes (no CapacityUnits, TableName or Table)'
    )
    floor_bytes = floor_cc['VectorSearchRequestBytes']
    assert floor_bytes == 1024.0, (
        f'VectorSearchRequestBytes was {floor_bytes!r}, expected 1024.0 (the 1 KB minimum)'
    )

    # ReturnConsumedCapacity=INDEXES reports the same flat shape as TOTAL for SearchVectors.
    indexes_cc = _search_until(ddb, table, 'idx-small', 1, _vec(_QUERY_SMALL),
                               lambda res: len(res) >= 1, return_consumed_capacity='INDEXES')
    assert indexes_cc == {'VectorSearchRequestBytes': 1024.0}, (
        f'ReturnConsumedCapacity=INDEXES on SearchVectors returned {indexes_cc!r}, '
        f'expected only VectorSearchRequestBytes at the 1024.0 floor'
    )

    # TopK growth, same index and query: more candidates scored means more bytes.
    topk1_cc = _search_until(ddb, table, 'idx-big', 1, query_big, lambda res: len(res) >= 1)
    topkn_cc = _search_until(ddb, table, 'idx-big', _N, query_big, lambda res: len(res) == _N)
    bytes_topk1 = topk1_cc['VectorSearchRequestBytes']
    bytes_topkn = topkn_cc['VectorSearchRequestBytes']
    assert bytes_topkn > bytes_topk1, (
        f'TopK={_N} reported {bytes_topkn!r} bytes, not more than TopK=1\'s {bytes_topk1!r}'
    )

    # Returning the searched vector attribute itself raises the meter over a projection that
    # withholds it, same TopK and query throughout.
    pk_only = ddb.search_vectors(TableName=table, IndexName='idx-big', TopK=1,
                                 SearchVector=query_big, ReturnConsumedCapacity='TOTAL',
                                 ProjectionExpression='pk')['ConsumedCapacity']['VectorSearchRequestBytes']
    with_vector = ddb.search_vectors(TableName=table, IndexName='idx-big', TopK=1,
                                     SearchVector=query_big, ReturnConsumedCapacity='TOTAL',
                                     ProjectionExpression='pk, emb_big')['ConsumedCapacity']['VectorSearchRequestBytes']
    assert with_vector > pk_only, (
        f'projecting in the vector attribute "emb_big" left VectorSearchRequestBytes at '
        f'{with_vector!r}, not more than {pk_only!r} without it'
    )


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


def _search_until(ddb, table, index, top_k, query, done, timeout_s=90, return_consumed_capacity='TOTAL'):
    deadline = time.time() + timeout_s
    out = {}
    while time.time() < deadline:
        out = ddb.search_vectors(TableName=table, IndexName=index, TopK=top_k, SearchVector=query,
                                 ReturnConsumedCapacity=return_consumed_capacity)
        if done(out.get('SearchResults', [])):
            return out.get('ConsumedCapacity') or {}
        time.sleep(1)
    raise AssertionError(f'{index}: TopK={top_k} never reached the expected result count in time')


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
