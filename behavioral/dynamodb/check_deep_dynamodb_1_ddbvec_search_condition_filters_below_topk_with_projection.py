"""deep-dynamodb-1-ddbvec-search-condition-filters-below-topk-with-projection."""
from __future__ import annotations

import math
import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-search-condition-filters-below-topk-with-projection"
GROUP = 'vector'
SERVICES = ['dynamodb']

# Six items, two of them in category "x". TopK is 10, larger than BOTH the matching subset (2)
# and the whole table (6), so the only thing that can shrink the result is the filter.
_ITEMS = {
    'a': ([1.0, 0.0, 0.0, 0.0], 'x'),
    'b': ([4.0, 1.0, 0.0, 0.0], 'y'),
    'c': ([0.5, 0.5, 0.0, 0.0], 'x'),
    'e': ([0.0, 0.0, 1.0, 0.0], 'y'),
    'f': ([-2.0, 0.0, 0.0, 0.0], 'y'),
    'g': ([1.0, 0.1, 0.0, 0.0], 'z'),
}
_QUERY = [1.0, 0.0, 0.0, 0.0]


def _euclid(u, v):
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(u, v)))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """An INLINE_FILTER condition returns only matching items nearest-first, fewer than TopK.

    ProjectionExpression trims each result to exactly the named attributes.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        # A SearchSchema attribute must be declared in AttributeDefinitions (CreateTable otherwise
        # fails "One element in SearchSchema is not defined in attribute definitions").
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'cat', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx-euc',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'EUCLIDEAN',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'cat', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    described = _wait_vector_table_active(ddb, table)
    schema = described['VectorIndexes'][0].get('SearchSchema')
    assert schema == [{'AttributeName': 'cat', 'SearchSchemaElementType': 'INLINE_FILTER'}], (
        f'the vector index search schema was described back as {schema!r}'
    )

    for pk, (vec, cat) in _ITEMS.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'emb': {'L': _vec(vec)},
                                            'cat': {'S': cat}, 'note': {'S': f'note-{pk}'},
                                            'extra': {'N': '7'}})

    # Positive control: unfiltered and unprojected, every item comes back with every attribute.
    control = _search_until(ddb, table, 10, lambda res: len(res) == len(_ITEMS))
    assert sorted(r['Item']['pk']['S'] for r in control) == sorted(_ITEMS), (
        f'unfiltered TopK=10 returned {[r["Item"]["pk"]["S"] for r in control]!r}, '
        f'expected all of {sorted(_ITEMS)!r}'
    )
    # ProjectionType ALL returns every non-vector attribute. The vector attribute itself is NOT
    # returned by SearchVectors.
    for r in control:
        assert set(r['Item']) == {'pk', 'cat', 'note', 'extra'}, (
            f'unprojected search item carried {sorted(r["Item"])!r}, expected pk, cat, note, extra'
        )

    want = sorted((pk for pk, (_, cat) in _ITEMS.items() if cat == 'x'),
                  key=lambda pk: _euclid(_QUERY, _ITEMS[pk][0]))
    assert want == ['a', 'c'], f'fixture premise broke: {want!r}'

    res = ddb.search_vectors(
        TableName=table, IndexName='idx-euc', TopK=10, SearchVector=_vec(_QUERY),
        SearchConditionExpression='#c = :x',
        ExpressionAttributeNames={'#c': 'cat'},
        ExpressionAttributeValues={':x': {'S': 'x'}},
        ProjectionExpression='pk, note',
    )['SearchResults']
    got = [r['Item'].get('pk', {}).get('S') for r in res]
    assert len(res) < 10, f'the filter did not shrink the result: {len(res)} items for TopK=10'
    assert got == want, f'filtered search returned {got!r}, expected exactly {want!r} nearest-first'
    for r in res:
        assert set(r['Item']) == {'pk', 'note'}, (
            f'ProjectionExpression "pk, note" returned attributes {sorted(r["Item"])!r}'
        )
        pk = r['Item']['pk']['S']
        assert r['Item']['note'] == {'S': f'note-{pk}'}, f'projected note was {r["Item"]["note"]!r}'
        assert abs(float(r['Score']) - _euclid(_QUERY, _ITEMS[pk][0])) < 1e-3, (
            f'item {pk!r} scored {r["Score"]!r} under the filter'
        )
        stored = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True)['Item']
        assert stored['cat'] == {'S': 'x'}, (
            f'filtered search returned {pk!r}, whose stored cat is {stored["cat"]!r}'
        )


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


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
        f'table/vector index never became ACTIVE: {tbl["TableStatus"]!r} '
        f'{[(v.get("IndexName"), v.get("IndexStatus")) for v in tbl.get("VectorIndexes", [])]!r}'
    )


def _search_until(ddb, table, top_k, done, timeout_s=90):
    deadline = time.time() + timeout_s
    res = []
    while time.time() < deadline:
        res = ddb.search_vectors(TableName=table, IndexName='idx-euc', TopK=top_k,
                                 SearchVector=_vec(_QUERY))['SearchResults']
        if done(res):
            return res
        time.sleep(1)
    return res


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
