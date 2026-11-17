"""search-vectors-expression-attribute-name-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-vectors-expression-attribute-name-mismatch-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [1.0, 0.0]

_UNDEFINED = ('ValidationException',
             'Invalid SearchConditionExpression: An expression attribute name used in the '
             'document path is not defined; attribute name: #c')
_UNUSED = ('ValidationException',
          'Value provided in ExpressionAttributeNames unused in expressions: keys: {#unused}')


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f'expected {code!r}, got {got_code!r} ({got_message!r})'
    assert got_message == message, f'expected message {message!r}, got {got_message!r}'


def _vec(values):
    return [{'N': str(v)} for v in values]


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


def _search_until(ddb, table, index, want_count, timeout_s=90, **kwargs):
    deadline = time.time() + timeout_s
    results = []
    while time.time() < deadline:
        results = ddb.search_vectors(TableName=table, IndexName=index, TopK=10,
                                     SearchVector=_vec(_QUERY), **kwargs)['SearchResults']
        if len(results) == want_count:
            return results
        time.sleep(1)
    raise AssertionError(
        f"never saw {want_count} search results within {timeout_s}s, last: {results!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors refuses a SearchConditionExpression naming an ExpressionAttributeNames
    placeholder with no entry, and refuses an ExpressionAttributeNames entry no placeholder
    references, each with its own ValidationException message; a correct call still succeeds."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecname-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'cat', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 2,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
            'SearchSchema': [{'AttributeName': 'cat', 'SearchSchemaElementType': 'INLINE_FILTER'}],
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)

    ddb.put_item(TableName=table, Item={'pk': {'S': 'p0'}, 'emb': {'L': _vec(_QUERY)},
                                        'cat': {'S': 'x'}})

    before = _search_until(ddb, table, 'idx', 1)
    assert before[0]['Item']['pk']['S'] == 'p0', (
        f"positive control before the refusal returned {before!r}, expected item 'p0'"
    )

    expect_error(
        lambda: ddb.search_vectors(
            TableName=table, IndexName='idx', TopK=10, SearchVector=_vec(_QUERY),
            SearchConditionExpression='#c = :x', ExpressionAttributeValues={':x': {'S': 'x'}},
        ),
        *_UNDEFINED,
    )
    expect_error(
        lambda: ddb.search_vectors(
            TableName=table, IndexName='idx', TopK=10, SearchVector=_vec(_QUERY),
            SearchConditionExpression='cat = :x',
            ExpressionAttributeNames={'#unused': 'cat'},
            ExpressionAttributeValues={':x': {'S': 'x'}},
        ),
        *_UNUSED,
    )

    after = _search_until(ddb, table, 'idx', 1)
    assert after[0]['Item']['pk']['S'] == 'p0', (
        f"positive control after the refusal returned {after!r}, expected item 'p0' unaffected"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
