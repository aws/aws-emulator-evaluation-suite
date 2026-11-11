"""deep-dynamodb-1-ddbvec-inline-filter-range-comparator-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-inline-filter-range-comparator-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [0.0, 0.0, 0.0, 0.0]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchConditionExpression filters by equality on an INLINE_FILTER attribute but refuses > and <.

    The model says range operators are supported; real AWS rejects them with ValidationException.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'price', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx-price',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'EUCLIDEAN',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'price', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)
    for i in range(4):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'p{i}'}, 'price': {'N': str(10 * i)},
                                            'emb': {'L': _vec([float(i), 0, 0, 0])}})

    got = []
    deadline = time.time() + 90
    while time.time() < deadline:
        got = [r['Item']['pk']['S'] for r in ddb.search_vectors(
            TableName=table, IndexName='idx-price', TopK=10,
            SearchVector=_vec(_QUERY))['SearchResults']]
        if len(got) == 4:
            break
        time.sleep(1)
    assert got == ['p0', 'p1', 'p2', 'p3'], f'unfiltered search returned {got!r}'

    eq = ddb.search_vectors(TableName=table, IndexName='idx-price', TopK=10,
                            SearchVector=_vec(_QUERY), SearchConditionExpression='price = :p',
                            ExpressionAttributeValues={':p': {'N': '20'}})['SearchResults']
    assert [r['Item']['pk']['S'] for r in eq] == ['p2'], (
        f'positive control: price = 20 returned {[r["Item"]["pk"]["S"] for r in eq]!r}'
    )

    for expr in ('price > :p', 'price < :p'):
        err = _error(lambda: ddb.search_vectors(
            TableName=table, IndexName='idx-price', TopK=10, SearchVector=_vec(_QUERY),
            SearchConditionExpression=expr, ExpressionAttributeValues={':p': {'N': '15'}}),
            f'SearchConditionExpression {expr!r} on an INLINE_FILTER attribute')
        assert err.get('Code') == 'ValidationException', (
            f'{expr!r}: expected ValidationException, got {err!r}'
        )
        expected_msg = ('Invalid SearchConditionExpression: Invalid comparator used in '
                        'SearchConditionExpression')
        assert err.get('Message') == expected_msg, (
            f'{expr!r}: expected message {expected_msg!r}, got {err.get("Message")!r}'
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
