"""search-vectors-non-numeric-search-vector-element-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-vectors-non-numeric-search-vector-element-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_BAD_SEARCH_VECTOR = ('ValidationException', 'Search vector contains invalid values. All '
                      'values in the search vector must be a 32-bit floating-point number '
                      'attribute')


def _vec(values):
    return [{'N': str(v)} for v in values]


def _error(fn):
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


def _search_until(ddb, table, index, top_k, search_vector, want_count, timeout_s=90):
    deadline = time.time() + timeout_s
    results = []
    while time.time() < deadline:
        results = ddb.search_vectors(TableName=table, IndexName=index, TopK=top_k,
                                     SearchVector=search_vector)['SearchResults']
        if len(results) == want_count:
            return results
        time.sleep(1)
    raise AssertionError(
        f"never saw {want_count} search results within {timeout_s}s, last: {results!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """SearchVectors refuses a SearchVector with a non-number element with ValidationException,
    and a correct call against the same index succeeds before and after the refusal."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ddbvecbad-')

    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        VectorIndexes=[{
            'IndexName': 'idx',
            'VectorAttribute': {'AttributeName': 'emb'},
            'Dimensions': 4,
            'DistanceFunction': 'COSINE',
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_vector_table_active(ddb, table)

    ddb.put_item(TableName=table, Item={'pk': {'S': 'p0'}, 'emb': {'L': _vec([1.0, 0.0, 0.0, 0.0])}})

    before = _search_until(ddb, table, 'idx', top_k=1, search_vector=_vec([1.0, 0.0, 0.0, 0.0]),
                           want_count=1)
    assert before[0]['Item']['pk']['S'] == 'p0', (
        f"positive control before the refusal returned {before!r}, expected item 'p0'"
    )

    bad_vector = [{'N': '1'}, {'S': 'x'}, {'N': '2'}, {'N': '3'}]
    expect_error(
        lambda: ddb.search_vectors(TableName=table, IndexName='idx', TopK=1,
                                   SearchVector=bad_vector),
        *_BAD_SEARCH_VECTOR,
    )

    after = _search_until(ddb, table, 'idx', top_k=1, search_vector=_vec([1.0, 0.0, 0.0, 0.0]),
                          want_count=1)
    assert after[0]['Item']['pk']['S'] == 'p0', (
        f"positive control after the refusal returned {after!r}, expected item 'p0' unaffected"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
