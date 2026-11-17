"""search-vectors-dot-product-score-rounds-integer-above-2-24-to-float32."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-vectors-dot-product-score-rounds-integer-above-2-24-to-float32"
GROUP = 'vector'
SERVICES = ['dynamodb']

# 2**24 is the largest integer every float32 represents exactly; 2**24 + 1 is the smallest
# positive integer float32 cannot, and rounds down to 2**24.
_UNROUNDED = 16777216
_UNREPRESENTABLE = 16777217


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
    """A DOT_PRODUCT index keeps a float32 copy of the embedding for scoring and projection: an
    integer above 2**24 rounds to the nearest float32, matching a neighbor already at that
    value, while GetItem on the base table keeps the full integer written."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecf32-')

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

    ddb.put_item(TableName=table, Item={'pk': {'S': 'unrepresentable'}, 'emb': {'L': _vec(_UNREPRESENTABLE)}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'unrounded'}, 'emb': {'L': _vec(_UNROUNDED)}})

    response = _search_until(ddb, table, 'idx', top_k=2, query=1.0, want_count=2)
    assert 'NextToken' not in response, (
        f"SearchVectors with TopK (2) equal to the item count still carried NextToken: "
        f"{response.get('NextToken')!r}"
    )
    results = response['SearchResults']
    assert len(results) == 2, f"TopK=2 over 2 items returned {len(results)}, expected both back"

    by_pk = {r['Item']['pk']['S']: r for r in results}
    assert set(by_pk) == {'unrepresentable', 'unrounded'}, (
        f"SearchVectors returned pks {sorted(by_pk)}, expected both seeded items"
    )

    unrepresentable_score = by_pk['unrepresentable']['Score']
    unrounded_score = by_pk['unrounded']['Score']
    assert repr(unrepresentable_score) == '16777216.0', (
        f"item written as {_UNREPRESENTABLE} scored {unrepresentable_score!r}, expected the "
        f"float32-rounded dot product 16777216.0 (the nearest float32 to {_UNREPRESENTABLE})"
    )
    assert repr(unrounded_score) == '16777216.0', (
        f"item written as {_UNROUNDED} scored {unrounded_score!r}, expected the exact dot "
        f"product 16777216.0 ({_UNROUNDED} is itself representable in float32)"
    )
    assert unrepresentable_score == unrounded_score, (
        f"a value float32 cannot represent ({_UNREPRESENTABLE}) scored "
        f"{unrepresentable_score!r}, a different value from its float32-exact neighbor "
        f"({_UNROUNDED}) at {unrounded_score!r} - the index copy should have collapsed them"
    )

    projected_unrepresentable = by_pk['unrepresentable']['Item']['emb']['L'][0]['N']
    projected_unrounded = by_pk['unrounded']['Item']['emb']['L'][0]['N']
    assert projected_unrepresentable == '16777216.0', (
        f"SearchVectors projected the vector attribute written as {_UNREPRESENTABLE} as "
        f"{projected_unrepresentable!r}, expected the float32-rounded '16777216.0'"
    )
    assert projected_unrounded == '16777216.0', (
        f"SearchVectors projected the vector attribute written as {_UNROUNDED} as "
        f"{projected_unrounded!r}, expected '16777216.0'"
    )

    stored_unrepresentable = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'unrepresentable'}}, ConsistentRead=True
    )['Item']['emb']['L'][0]['N']
    stored_unrounded = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'unrounded'}}, ConsistentRead=True
    )['Item']['emb']['L'][0]['N']
    assert stored_unrepresentable == str(_UNREPRESENTABLE), (
        f"GetItem on the base table returned {stored_unrepresentable!r} for the vector "
        f"component written as {_UNREPRESENTABLE}, expected the full-precision "
        f"{str(_UNREPRESENTABLE)!r} unrounded"
    )
    assert stored_unrounded == str(_UNROUNDED), (
        f"GetItem on the base table returned {stored_unrounded!r} for the vector component "
        f"written as {_UNROUNDED}, expected the full-precision {str(_UNROUNDED)!r}"
    )
    assert stored_unrepresentable != projected_unrepresentable, (
        f"GetItem on the base table ({stored_unrepresentable!r}) and SearchVectors' projected "
        f"vector ({projected_unrepresentable!r}) agreed for a value float32 cannot represent "
        f"exactly - expected the base table to keep full precision while the index's "
        f"projected copy carries the float32-rounded value"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
