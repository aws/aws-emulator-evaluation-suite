"""search-vectors-dot-product-order-and-score-precision."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-vectors-dot-product-order-and-score-precision"
GROUP = 'vector'
SERVICES = ['dynamodb']

_ITEMS = {'a': 2.0, 'b': 0.0, 'c': -3.0, 'd': 0.1}


def _vec(value):
    return [{'N': str(value)}]


def _wait_vector_table_active(ddb, table, timeout_s=240):
    deadline = time.time() + timeout_s
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    tbl = ddb.describe_table(TableName=table)['Table']
    assert tbl.get('VectorIndexes'), (
        'CreateTable accepted VectorIndexes but DescribeTable reports none - the vector index '
        'was silently dropped'
    )
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)['Table']
        if tbl['TableStatus'] == 'ACTIVE' and all(
                v.get('IndexStatus') == 'ACTIVE' for v in tbl.get('VectorIndexes', [])):
            return tbl
        time.sleep(2)
    raise AssertionError(
        f"table/vector index never became ACTIVE: {tbl['TableStatus']!r} "
        f"{[(v.get('IndexName'), v.get('IndexStatus')) for v in tbl.get('VectorIndexes', [])]!r}"
    )


def _search_until(ddb, table, index, top_k, query, want_count, timeout_s=90):
    deadline = time.time() + timeout_s
    response = {}
    while time.time() < deadline:
        response = ddb.search_vectors(TableName=table, IndexName=index, TopK=top_k,
                                      SearchVector=_vec(query),
                                      ProjectionExpression='pk, emb')
        if len(response.get('SearchResults', [])) == want_count:
            return response
        time.sleep(1)
    raise AssertionError(
        f"never saw {want_count} search results within {timeout_s}s, last: {response!r}"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors on a DOT_PRODUCT index ranks the highest score first, including negative
    scores, and a TopK above the item count returns every item with no NextToken or
    LastEvaluatedKey. Score reflects float32 math; a projected vector keeps full precision."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecprec-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 1,
            'DistanceFunction': 'DOT_PRODUCT',
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)

    for pk, value in _ITEMS.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'emb': {'L': _vec(value)}})

    response = _search_until(ddb, table, 'idx', top_k=10, query=1.0, want_count=len(_ITEMS))
    assert 'NextToken' not in response, (
        f"SearchVectors with TopK ({10}) above the item count ({len(_ITEMS)}) still carried "
        f"NextToken: {response.get('NextToken')!r}"
    )
    assert 'LastEvaluatedKey' not in response, (
        f"SearchVectors with TopK ({10}) above the item count ({len(_ITEMS)}) still carried "
        f"LastEvaluatedKey: {response.get('LastEvaluatedKey')!r}"
    )
    results = response['SearchResults']
    assert len(results) == len(_ITEMS), (
        f"TopK=10 over {len(_ITEMS)} items returned {len(results)}, expected every item back"
    )

    ordered = [(r['Item']['pk']['S'], r['Score']) for r in results]
    ordered_pks = [pk for pk, _ in ordered]
    assert ordered_pks == ['a', 'd', 'b', 'c'], (
        f"DOT_PRODUCT must rank the highest score first, got {ordered_pks!r}"
    )
    scores = [score for _, score in ordered]
    assert scores == sorted(scores, reverse=True), (
        f"DOT_PRODUCT scores were not descending: {scores!r}"
    )
    assert repr(scores[0]) == '2.0', f"item 'a' scored {scores[0]!r}, expected 2.0"
    assert repr(scores[1]) == '0.10000000149011612', (
        f"item 'd' scored {scores[1]!r}, expected the float32-rounded dot product "
        f"of 0.1 with the query vector"
    )
    assert repr(scores[2]) == '0.0', f"item 'b' scored {scores[2]!r}, expected 0.0"
    assert repr(scores[3]) == '-3.0', (
        f"item 'c' scored {scores[3]!r}, expected the negative score -3.0"
    )

    by_pk = {r['Item']['pk']['S']: r['Item'] for r in results}
    searched_emb = by_pk['d']['emb']['L'][0]['N']
    assert searched_emb == '0.1', (
        f"SearchVectors projected the vector attribute as {searched_emb!r}, expected the "
        f"full-precision '0.1' as written"
    )

    stored = ddb.get_item(TableName=table, Key={'pk': {'S': 'd'}}, ConsistentRead=True)['Item']
    stored_emb = stored['emb']['L'][0]['N']
    assert stored_emb == '0.1', (
        f"GetItem on the base table returned {stored_emb!r} for the written vector component, "
        f"expected the full-precision '0.1' as written"
    )
    assert stored_emb == searched_emb, (
        f"GetItem returned {stored_emb!r} but SearchVectors projected {searched_emb!r} for the "
        f"same written vector component"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
