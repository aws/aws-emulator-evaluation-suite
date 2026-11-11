"""deep-dynamodb-1-ddbvec-hash-schema-search-without-condition-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-dynamodb-1-ddbvec-hash-schema-search-without-condition-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [0.0, 0.0, 0.0, 0.0]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """A HASH search-schema vector index returns only the conditioned tenant's items, nearest-first.

    SearchVectors without a SearchConditionExpression on it is a ValidationException, not a
    cross-tenant result.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvec-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'tenant', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx-tenant',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'EUCLIDEAN',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'tenant', 'SearchSchemaElementType': 'HASH'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)

    # Tenant t2 holds the vectors nearest the origin; t1's are farther out.
    items = {'t1-a': ('t1', 3.0), 't1-b': ('t1', 5.0), 't1-c': ('t1', 4.0),
             't2-a': ('t2', 0.0), 't2-b': ('t2', 1.0)}
    for pk, (tenant, x) in items.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'tenant': {'S': tenant},
                                            'emb': {'L': _vec([x, 0, 0, 0])}})

    def _tenant(t):
        return ddb.search_vectors(TableName=table, IndexName='idx-tenant', TopK=10,
                                  SearchVector=_vec(_QUERY), SearchConditionExpression='tenant = :t',
                                  ExpressionAttributeValues={':t': {'S': t}})['SearchResults']

    got = {}
    deadline = time.time() + 90
    while time.time() < deadline:
        got = {t: [r['Item']['pk']['S'] for r in _tenant(t)] for t in ('t1', 't2')}
        if len(got['t1']) == 3 and len(got['t2']) == 2:
            break
        time.sleep(1)
    assert got == {'t1': ['t1-a', 't1-c', 't1-b'], 't2': ['t2-a', 't2-b']}, (
        f'positive control: per-tenant searches returned {got!r}'
    )

    err = _error(lambda: ddb.search_vectors(TableName=table, IndexName='idx-tenant', TopK=10,
                                            SearchVector=_vec(_QUERY)),
                 'SearchVectors with no condition on a HASH-partitioned vector index')
    assert err.get('Code') == 'ValidationException', f'expected ValidationException, got {err!r}'
    expected_msg = 'SearchConditionExpression must be provided when SearchSchema has a HASH key'
    assert err.get('Message') == expected_msg, (
        f'expected message {expected_msg!r}, got {err.get("Message")!r}'
    )
    # Unchanged state: the partitions still answer exactly as before.
    again = [r['Item']['pk']['S'] for r in _tenant('t1')]
    assert again == ['t1-a', 't1-c', 't1-b'], f't1 after the refusal returned {again!r}'


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
