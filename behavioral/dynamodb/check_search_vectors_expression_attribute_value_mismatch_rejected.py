"""search-vectors-expression-attribute-value-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-vectors-expression-attribute-value-mismatch-rejected"
GROUP = 'vector'
SERVICES = ['dynamodb']

_QUERY = [0.0, 0.0, 0.0, 0.0]

_UNDEFINED = ('ValidationException',
             'Invalid SearchConditionExpression: An expression attribute value used in '
             'expression is not defined; attribute value: :p')
_UNUSED = ('ValidationException',
          'Value provided in ExpressionAttributeValues unused in expressions: keys: {:unused}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """A SearchConditionExpression placeholder with no matching ExpressionAttributeValues entry,
    and an ExpressionAttributeValues entry no placeholder references, both refuse the search.
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
    ddb.put_item(TableName=table, Item={'pk': {'S': 'p0'}, 'price': {'N': '10'},
                                        'emb': {'L': _vec([1, 0, 0, 0])}})

    # Positive control: the attribute value is defined and used, so the filter applies.
    control = []
    deadline = time.time() + 90
    while time.time() < deadline:
        control = ddb.search_vectors(TableName=table, IndexName='idx-price', TopK=10,
                                     SearchVector=_vec(_QUERY), SearchConditionExpression='price = :p',
                                     ExpressionAttributeValues={':p': {'N': '10'}})['SearchResults']
        if control:
            break
        time.sleep(1)
    assert [r['Item']['pk']['S'] for r in control] == ['p0'], (
        f'positive control: price = 10 returned {[r["Item"]["pk"]["S"] for r in control]!r}'
    )

    expect_error(
        lambda: ddb.search_vectors(TableName=table, IndexName='idx-price', TopK=10,
                                   SearchVector=_vec(_QUERY), SearchConditionExpression='price = :p'),
        *_UNDEFINED,
    )

    expect_error(
        lambda: ddb.search_vectors(TableName=table, IndexName='idx-price', TopK=10,
                                   SearchVector=_vec(_QUERY), SearchConditionExpression='price = :p',
                                   ExpressionAttributeValues={':p': {'N': '10'}, ':unused': {'S': 'x'}}),
        *_UNUSED,
    )


def _vec(values):
    return [{'N': repr(float(x))} for x in values]


def expect_error(fn, code, message):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 -- the Error.Code/Message IS the assertion
        err = (getattr(exc, 'response', None) or {}).get('Error')
        if not err:
            raise AssertionError(f'expected a service error, raised {exc!r} instead') from exc
        assert err.get('Code') == code, f'expected error code {code!r}, got {err!r}'
        assert err.get('Message') == message, f'expected message {message!r}, got {err.get("Message")!r}'
        return
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


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
