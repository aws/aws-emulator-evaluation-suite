"""deep-dynamodb-1-ddbvec-condition-on-non-schema-attribute-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-condition-on-non-schema-attribute-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [1.0, 0.0, 0.0, 0.0]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors filtering on the index's INLINE_FILTER attribute returns the matching item, while filtering
    on a projected attribute outside the SearchSchema raises ValidationException with the exact message.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'cat', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx-cos',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'cat', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)
    for pk, cat in (('a', 'x'), ('b', 'y')):
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'emb': {'L': _vec(_QUERY)},
                                            'cat': {'S': cat}, 'note': {'S': f'n-{pk}'}})

    got = []
    deadline = time.time() + 90
    while time.time() < deadline:
        res = ddb.search_vectors(TableName=table, IndexName='idx-cos', TopK=5,
                                 SearchVector=_vec(_QUERY))['SearchResults']
        got = sorted(r['Item']['pk']['S'] for r in res)
        if got == ['a', 'b']:
            break
        time.sleep(1)
    assert got == ['a', 'b'], f'both items should be searchable, got {got!r}'
    assert all(r['Item'].get('note') for r in res), (
        f'note is projected into the index and must be returned: {res!r}'
    )

    ok = ddb.search_vectors(TableName=table, IndexName='idx-cos', TopK=5,
                            SearchVector=_vec(_QUERY), SearchConditionExpression='cat = :v',
                            ExpressionAttributeValues={':v': {'S': 'x'}})['SearchResults']
    assert [r['Item']['pk']['S'] for r in ok] == ['a'], (
        f'positive control: filtering on schema attribute cat returned {ok!r}'
    )

    err = _error(lambda: ddb.search_vectors(
        TableName=table, IndexName='idx-cos', TopK=5, SearchVector=_vec(_QUERY),
        SearchConditionExpression='note = :v', ExpressionAttributeValues={':v': {'S': 'n-a'}}),
        'SearchConditionExpression on non-schema attribute note')
    assert err.get('Code') == 'ValidationException', f'expected ValidationException, got {err!r}'
    expected_msg = ('SearchConditionExpression must not contain any attributes that is not in '
                    'SearchSchema. Invalid attribute: note')
    assert err.get('Message') == expected_msg, (
        f'expected message {expected_msg!r}, got {err.get("Message")!r}'
    )


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


def _error(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        err = (getattr(exc, 'response', None) or {}).get('Error')
        if not err:
            raise AssertionError(f'{what}: raised a non-service error {exc!r}') from exc
        return err
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


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
