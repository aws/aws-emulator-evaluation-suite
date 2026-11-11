"""deep-dynamodb-1-ddbvec-distance-functions-invert-topk-selection."""
from __future__ import annotations

import math
import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-distance-functions-invert-topk-selection"
GROUP = 'vector'
SERVICES = ['dynamodb']

# One 4-d attribute, five items chosen so the three metrics disagree on WHICH three items are
# the top-3, not merely on their order. Query q = [1, 0, 0, 0].
#   item   vector          cosine dist   euclidean     dot product
#   a      [1, 0, 0, 0]    0             0             1
#   b      [4, 1, 0, 0]    0.02986       3.16228       4
#   c      [0.5,0.5,0,0]   0.29289       0.70711       0.5
#   e      [0, 0, 1, 0]    1             1.41421       0
#   f      [-2, 0, 0, 0]   2             3             -2
_ITEMS = {
    'a': [1.0, 0.0, 0.0, 0.0],
    'b': [4.0, 1.0, 0.0, 0.0],
    'c': [0.5, 0.5, 0.0, 0.0],
    'e': [0.0, 0.0, 1.0, 0.0],
    'f': [-2.0, 0.0, 0.0, 0.0],
}
_QUERY = [1.0, 0.0, 0.0, 0.0]


def _cos_dist(u, v):
    dot = sum(x * y for x, y in zip(u, v))
    return 1.0 - dot / (math.sqrt(sum(x * x for x in u)) * math.sqrt(sum(y * y for y in v)))


def _euclid(u, v):
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(u, v)))


def _dot(u, v):
    return sum(x * y for x, y in zip(u, v))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors TopK takes k smallest scores for COSINE/EUCLIDEAN, k highest for DOT_PRODUCT.

    Three indexes over one attribute must select three different top-3 sets for the same query.
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
        VectorIndexes=[_vi('idx-cos', 'COSINE'), _vi('idx-euc', 'EUCLIDEAN'),
                       _vi('idx-dot', 'DOT_PRODUCT')],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    described = _wait_vector_table_active(ddb, table)
    by_name = {v['IndexName']: v for v in described.get('VectorIndexes', [])}
    assert {n: by_name[n]['DistanceFunction'] for n in by_name} == {
        'idx-cos': 'COSINE', 'idx-euc': 'EUCLIDEAN', 'idx-dot': 'DOT_PRODUCT'}, (
        f'DescribeTable vector indexes were {sorted((n, v.get("DistanceFunction")) for n, v in by_name.items())!r}'
    )

    for pk, vec in _ITEMS.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'emb': {'L': _vec(vec)}})

    expected = {
        'idx-cos': sorted(_ITEMS, key=lambda k: _cos_dist(_QUERY, _ITEMS[k]))[:3],
        'idx-euc': sorted(_ITEMS, key=lambda k: _euclid(_QUERY, _ITEMS[k]))[:3],
        'idx-dot': sorted(_ITEMS, key=lambda k: -_dot(_QUERY, _ITEMS[k]))[:3],
    }
    # The design premise, pinned so a future edit to _ITEMS cannot silently collapse it.
    assert expected == {'idx-cos': ['a', 'b', 'c'], 'idx-euc': ['a', 'c', 'e'],
                        'idx-dot': ['b', 'a', 'c']}, f'fixture premise broke: {expected!r}'

    # Writes become searchable asynchronously; poll the full population (TopK=5) on every index
    # until all five items are visible before grading the TopK=3 selection.
    for idx in expected:
        full = _search_until(ddb, table, idx, 5, lambda res: len(res) == 5)
        assert len(full) == 5, f'{idx}: only {len(full)} of 5 written items became searchable'

    metric = {'idx-cos': _cos_dist, 'idx-euc': _euclid, 'idx-dot': _dot}
    got = {}
    for idx, want in expected.items():
        res = ddb.search_vectors(TableName=table, IndexName=idx, TopK=3,
                                 SearchVector=_vec(_QUERY))['SearchResults']
        scored = [(r['Item']['pk']['S'], float(r['Score'])) for r in res]
        got[idx] = scored
        assert [pk for pk, _ in scored] == want, (
            f'{idx}: TopK=3 selected {scored!r}, expected the items {want!r}'
        )
        for pk, score in scored:
            ref = metric[idx](_QUERY, _ITEMS[pk])
            assert abs(score - ref) < 1e-3, (
                f'{idx}: item {pk!r} scored {score!r}, the metric gives {ref!r}'
            )

    cos_scores = [s for _, s in got['idx-cos']]
    euc_scores = [s for _, s in got['idx-euc']]
    dot_scores = [s for _, s in got['idx-dot']]
    assert cos_scores == sorted(cos_scores), f'COSINE scores not ascending: {cos_scores!r}'
    assert euc_scores == sorted(euc_scores), f'EUCLIDEAN scores not ascending: {euc_scores!r}'
    assert dot_scores == sorted(dot_scores, reverse=True), (
        f'DOT_PRODUCT scores not descending: {dot_scores!r}'
    )
    # The inversion itself: item b is in the dot-product top-3 at rank 1 and excluded from the
    # euclidean top-3, because it is the farthest point yet has the largest dot product.
    assert got['idx-dot'][0][0] == 'b' and 'b' not in [pk for pk, _ in got['idx-euc']], (
        f'dot top-3 {got["idx-dot"]!r} vs euclidean top-3 {got["idx-euc"]!r}: '
        f'DOT_PRODUCT must take the k HIGHEST scores and EUCLIDEAN the k SMALLEST'
    )


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


def _search_until(ddb, table, index, top_k, done, timeout_s=90, **kw):
    deadline = time.time() + timeout_s
    res = []
    while time.time() < deadline:
        res = ddb.search_vectors(TableName=table, IndexName=index, TopK=top_k,
                                 SearchVector=_vec(_QUERY), **kw)['SearchResults']
        if done(res):
            return res
        time.sleep(1)
    return res


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
