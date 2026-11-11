"""deep-dynamodb-1-ddbvec-include-projection-hides-unprojected-attributes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-include-projection-hides-unprojected-attributes"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [0.0, 0.0, 0.0, 0.0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """An INCLUDE-projected vector index returns only keys, schema attributes and NonKeyAttributes.

    A ProjectionExpression naming an unprojected stored attribute silently omits it rather than
    reading it from the base table.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'tier', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx-incl',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'EUCLIDEAN',
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['note']},
            'SearchSchema': [{'AttributeName': 'tier', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    tbl = _wait_vector_table_active(ddb, table)
    proj = tbl['VectorIndexes'][0].get('Projection')
    assert proj == {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['note']}, (
        f'index projection described back as {proj!r}'
    )

    for i in range(3):
        ddb.put_item(TableName=table, Item={
            'pk': {'S': f'k{i}'}, 'tier': {'S': 'gold'}, 'note': {'S': f'note-{i}'},
            'secret': {'S': f'secret-{i}'}, 'emb': {'L': _vec([float(i), 0, 0, 0])}})
    stored = ddb.get_item(TableName=table, Key={'pk': {'S': 'k0'}}, ConsistentRead=True)['Item']
    assert set(stored) == {'pk', 'tier', 'note', 'secret', 'emb'}, f'stored item is {stored!r}'

    res = []
    deadline = time.time() + 90
    while time.time() < deadline:
        res = ddb.search_vectors(TableName=table, IndexName='idx-incl', TopK=10,
                                 SearchVector=_vec(_QUERY))['SearchResults']
        if len(res) == 3:
            break
        time.sleep(1)
    assert [r['Item']['pk']['S'] for r in res] == ['k0', 'k1', 'k2'], (
        f'search returned {[r["Item"].get("pk") for r in res]!r}'
    )
    for r in res:
        i = r['Item']['pk']['S'][1:]
        assert set(r['Item']) == {'pk', 'tier', 'note'}, (
            f'INCLUDE[note] index returned attributes {sorted(r["Item"])!r}; expected pk, tier, note'
        )
        assert r['Item']['note'] == {'S': f'note-{i}'}, f'included note was {r["Item"]["note"]!r}'

    widened = ddb.search_vectors(TableName=table, IndexName='idx-incl', TopK=10,
                                 SearchVector=_vec(_QUERY),
                                 ProjectionExpression='secret, note')['SearchResults']
    assert len(widened) == 3, f'projected search returned {len(widened)} items, expected 3'
    for r in widened:
        assert set(r['Item']) == {'note'}, (
            f'ProjectionExpression "secret, note" on an INCLUDE[note] index returned '
            f'{sorted(r["Item"])!r}; an unprojected attribute must not be retrievable'
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
